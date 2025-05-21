using System.Security.Cryptography;
using System.Text.Json;
using CRM.Security.KeyManagement.Models;
using CRM.Security.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CRM.Security.KeyManagement;

public class FileSystemKeyManager : IKeyManager
{
    private readonly KeyManagementOptions _options;
    private readonly ILogger<FileSystemKeyManager> _logger;
    private KeyPair _cachedKeyPair;
    private DateTime _cacheTime = DateTime.MinValue;
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(10);

    public FileSystemKeyManager(
        IOptions<KeyManagementOptions> options,
        ILogger<FileSystemKeyManager> logger, KeyPair cachedKeyPair)
    {
        _options = options.Value;
        _logger = logger;
        _cachedKeyPair = cachedKeyPair;

        EnsureKeyStorageExists();
    }

    public async Task<KeyPair> GetCurrentServiceKeys()
    {
        if (_cachedKeyPair != null && (DateTime.UtcNow - _cacheTime) < CacheDuration)
        {
            return _cachedKeyPair;
        }

        var keyInfo = await GetCurrentKeyInfo();
        if (keyInfo == null)
        {
            await RotateKeys();
            keyInfo = await GetCurrentKeyInfo();
        }

        var privateKeyPath = GetPrivateKeyPath(keyInfo!.KeyId);
        var publicKeyPath = GetPublicKeyPath(keyInfo.KeyId);

        if (!File.Exists(privateKeyPath) || !File.Exists(publicKeyPath))
        {
            throw new FileNotFoundException($"Key files not found for key ID {keyInfo.KeyId}");
        }

        var privateKey = await File.ReadAllTextAsync(privateKeyPath);
        var publicKey = await File.ReadAllTextAsync(publicKeyPath);

        _cachedKeyPair = new KeyPair
        {
            PrivateKey = privateKey,
            PublicKey = publicKey
        };

        _cacheTime = DateTime.UtcNow;

        return _cachedKeyPair;
    }

    public async Task<string> GetPublicKeyForService(string serviceId)
    {
        if (serviceId == _options.ServiceId)
        {
            var keys = await GetCurrentServiceKeys();
            return keys.PublicKey;
        }

        var keyDirectory = Path.Combine(_options.KeysPath, "remote", serviceId);

        if (!Directory.Exists(keyDirectory))
        {
            throw new DirectoryNotFoundException($"No keys found for service {serviceId}");
        }

        var keyInfoPath = Path.Combine(keyDirectory, "key-info.json");

        if (!File.Exists(keyInfoPath))
        {
            throw new FileNotFoundException($"Key info not found for service {serviceId}");
        }

        var keyInfoJson = await File.ReadAllTextAsync(keyInfoPath);
        var keyInfoList = JsonSerializer.Deserialize<List<KeyInfo>>(keyInfoJson);

        var activeKey = keyInfoList!
            .Where(k => k.Status == KeyStatus.Active && (k.ExpiresAt == null || k.ExpiresAt > DateTime.UtcNow))
            .OrderByDescending(k => k.CreatedAt)
            .FirstOrDefault();

        if (activeKey == null)
        {
            throw new InvalidOperationException($"No active key found for service {serviceId}");
        }

        var publicKeyPath = Path.Combine(keyDirectory, $"{activeKey.KeyId}.pub");

        if (!File.Exists(publicKeyPath))
        {
            throw new FileNotFoundException($"Public key not found for service {serviceId}, key ID {activeKey.KeyId}");
        }

        return await File.ReadAllTextAsync(publicKeyPath);
    }

    public Task<string> GetCurrentServiceId()
    {
        return Task.FromResult(_options.ServiceId);
    }

    public async Task<KeyInfo?> GetCurrentKeyInfo()
    {
        var keyInfoPath = GetKeyInfoPath();

        if (!File.Exists(keyInfoPath))
        {
            return null;
        }

        var keyInfoJson = await File.ReadAllTextAsync(keyInfoPath);
        List<KeyInfo> keyInfoList = JsonSerializer.Deserialize<List<KeyInfo>>(keyInfoJson) ?? new List<KeyInfo>();

        return keyInfoList
            .Where(k => k!.Status == KeyStatus.Active && (k.ExpiresAt == null || k.ExpiresAt > DateTime.UtcNow))
            .OrderByDescending(k => k!.CreatedAt)
            .FirstOrDefault();
    }

    public async Task RotateKeys(TimeSpan? validity = null)
    {
        try
        {
            _logger.LogInformation("Rotating keys for service {ServiceId}", _options.ServiceId);

            var keyValidity = validity ?? TimeSpan.FromDays(_options.KeyRotationDays);
            var keyId = Guid.NewGuid().ToString("N");

            using var rsa = RSA.Create(4096);
            var privateKey = rsa.ExportRSAPrivateKeyPem();
            var publicKey = rsa.ExportRSAPublicKeyPem();

            var privateKeyPath = GetPrivateKeyPath(keyId);
            var publicKeyPath = GetPublicKeyPath(keyId);

            await File.WriteAllTextAsync(privateKeyPath, privateKey);
            await File.WriteAllTextAsync(publicKeyPath, publicKey);

            if (OperatingSystem.IsLinux() && _options.SetSecurePermissions)
            {
                SetSecureFilePermissions(privateKeyPath);
            }

            var keyInfo = new KeyInfo
            {
                KeyId = keyId,
                ServiceId = _options.ServiceId,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.Add(keyValidity),
                Status = KeyStatus.Active
            };

            await UpdateKeyInfoAsync(keyInfo);

            _cachedKeyPair = new KeyPair
            {
                PrivateKey = privateKey,
                PublicKey = publicKey
            };

            _cacheTime = DateTime.UtcNow;

            _logger.LogInformation("Key rotation completed for service {ServiceId}", _options.ServiceId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to rotate keys for service {ServiceId}", _options.ServiceId);
            throw;
        }
    }

    public async Task RevokeKey(string keyId)
    {
        var keyInfoPath = GetKeyInfoPath();

        if (!File.Exists(keyInfoPath))
        {
            throw new FileNotFoundException($"Key info not found");
        }

        var keyInfoJson = await File.ReadAllTextAsync(keyInfoPath);
        var keyInfoList = JsonSerializer.Deserialize<List<KeyInfo>>(keyInfoJson) ?? new List<KeyInfo>();

        var keyToRevoke = keyInfoList.FirstOrDefault(k => k.KeyId == keyId);

        if (keyToRevoke == null)
        {
            throw new KeyNotFoundException($"Key with ID {keyId} not found");
        }

        keyToRevoke.Status = KeyStatus.Revoked;

        await File.WriteAllTextAsync(keyInfoPath, JsonSerializer.Serialize(keyInfoList));

        _logger.LogInformation("Key {KeyId} revoked for service {ServiceId}", keyId, _options.ServiceId);
    }

    public async Task<bool> ValidateKey(string keyId)
    {
        var keyInfoPath = GetKeyInfoPath();

        if (!File.Exists(keyInfoPath))
        {
            return false;
        }

        var keyInfoJson = await File.ReadAllTextAsync(keyInfoPath);
        var keyInfoList = JsonSerializer.Deserialize<List<KeyInfo>>(keyInfoJson) ?? new List<KeyInfo>();

        var keyInfo = keyInfoList.FirstOrDefault(k => k.KeyId == keyId);

        return keyInfo != null &&
               (keyInfo.Status == KeyStatus.Active || keyInfo.Status == KeyStatus.Backup) &&
               (keyInfo.ExpiresAt == null || keyInfo.ExpiresAt > DateTime.UtcNow);
    }

    private async Task UpdateKeyInfoAsync(KeyInfo newKeyInfo)
    {
        var keyInfoPath = GetKeyInfoPath();
        List<KeyInfo> keyInfoList;

        if (File.Exists(keyInfoPath))
        {
            var keyInfoJson = await File.ReadAllTextAsync(keyInfoPath);
            keyInfoList = JsonSerializer.Deserialize<List<KeyInfo>>(keyInfoJson) ?? new List<KeyInfo>();

            var oldActiveKeys = keyInfoList.Where(k => k.Status == KeyStatus.Active).ToList();
            foreach (var key in oldActiveKeys)
            {
                key.Status = KeyStatus.Backup;
            }
        }
        else
        {
            keyInfoList = new List<KeyInfo>();
        }

        keyInfoList.Add(newKeyInfo);

        await File.WriteAllTextAsync(keyInfoPath, JsonSerializer.Serialize(keyInfoList));
    }

    private string GetKeyDirectory()
    {
        return Path.Combine(_options.KeysPath, _options.ServiceId);
    }

    private string GetKeyInfoPath()
    {
        return Path.Combine(GetKeyDirectory(), "key-info.json");
    }

    private string GetPrivateKeyPath(string keyId)
    {
        return Path.Combine(GetKeyDirectory(), $"{keyId}.key");
    }

    private string GetPublicKeyPath(string keyId)
    {
        return Path.Combine(GetKeyDirectory(), $"{keyId}.pub");
    }

    private void EnsureKeyStorageExists()
    {
        if (!Directory.Exists(_options.KeysPath) && _options.CreateDirectoryIfNotExists)
        {
            Directory.CreateDirectory(_options.KeysPath);

            if (OperatingSystem.IsLinux() && _options.SetSecurePermissions)
            {
                SetSecureDirectoryPermissions(_options.KeysPath);
            }
        }

        var keyDirectory = GetKeyDirectory();

        if (!Directory.Exists(keyDirectory) && _options.CreateDirectoryIfNotExists)
        {
            Directory.CreateDirectory(keyDirectory);

            if (OperatingSystem.IsLinux() && _options.SetSecurePermissions)
            {
                SetSecureDirectoryPermissions(keyDirectory);
            }
        }

        var remoteDirectory = Path.Combine(_options.KeysPath, "remote");

        if (!Directory.Exists(remoteDirectory) && _options.CreateDirectoryIfNotExists)
        {
            Directory.CreateDirectory(remoteDirectory);

            if (OperatingSystem.IsLinux() && _options.SetSecurePermissions)
            {
                SetSecureDirectoryPermissions(remoteDirectory);
            }
        }
    }

    private void SetSecureFilePermissions(string filePath)
    {
        try
        {
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "chmod",
                    Arguments = $"600 {filePath}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to set secure file permissions for {FilePath}", filePath);
        }
    }

    private void SetSecureDirectoryPermissions(string directoryPath)
    {
        try
        {
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "chmod",
                    Arguments = $"700 {directoryPath}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to set secure directory permissions for {DirectoryPath}", directoryPath);
        }
    }
}