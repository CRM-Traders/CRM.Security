using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CRM.Security.Encryption.Models;
using CRM.Security.KeyManagement;
using CRM.Security.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace CRM.Security.Encryption;

public class EncryptionService : IEncryptionService
{
    private readonly IKeyManager _keyManager;
    private readonly ILogger<EncryptionService> _logger;
    private readonly EncryptionOptions _options;

    public EncryptionService(
        IKeyManager keyManager,
        IOptions<EncryptionOptions> options,
        ILogger<EncryptionService> logger)
    {
        _keyManager = keyManager;
        _logger = logger;
        _options = options.Value;
    }

    public async Task<string> EncryptForClient<T>(T data, string publicKey)
    {
        try
        {
            var serialized = JsonSerializer.Serialize(data);
            
            using var aes = Aes.Create();
            aes.KeySize = _options.KeySize;
            aes.GenerateKey();
            aes.GenerateIV();
            
            byte[] encryptedData;
            using (var encryptor = aes.CreateEncryptor())
            using (var memoryStream = new MemoryStream())
            {
                await using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                await using (var writer = new StreamWriter(cryptoStream))
                {
                    writer.Write(serialized);
                }
                
                encryptedData = memoryStream.ToArray();
            }
            
            byte[] encryptedKey;
            using (var rsa = RSA.Create())
            {
                if (publicKey.Contains("-----BEGIN PUBLIC KEY-----"))
                {
                    rsa.ImportFromPem(publicKey);
                }
                else
                {
                    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                }
                
                encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
            }
            
            var package = new EncryptedPackage
            {
                Key = Convert.ToBase64String(encryptedKey),
                Iv = Convert.ToBase64String(aes.IV),
                Data = Convert.ToBase64String(encryptedData),
                Algorithm = "AES256_RSA",
                Version = "1.0",
                Compressed = false
            };
            
            return JsonSerializer.Serialize(package);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to encrypt data for client");
            throw;
        }
    }

    public async Task<T> DecryptFromClient<T>(string encryptedData, string privateKey)
    {
        try
        {
            var package = JsonSerializer.Deserialize<EncryptedPackage>(encryptedData) 
                ?? throw new InvalidOperationException("Invalid encrypted package format");
            
            byte[] encryptedBytes = Convert.FromBase64String(package.Data);
            byte[] encryptedKeyBytes = Convert.FromBase64String(package.Key);
            byte[] ivBytes = Convert.FromBase64String(package.Iv);
            
            byte[] decryptedKey;
            using (var rsa = RSA.Create())
            {
                if (privateKey.Contains("-----BEGIN PRIVATE KEY-----"))
                {
                    rsa.ImportFromPem(privateKey);
                }
                else
                {
                    rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);
                }
                
                decryptedKey = rsa.Decrypt(encryptedKeyBytes, RSAEncryptionPadding.OaepSHA256);
            }
            
            string decrypted;
            using (var aes = Aes.Create())
            {
                aes.Key = decryptedKey;
                aes.IV = ivBytes;
                
                using var decryptor = aes.CreateDecryptor();
                using var memoryStream = new MemoryStream(encryptedBytes);
                await using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                using var reader = new StreamReader(cryptoStream);
                
                decrypted = await reader.ReadToEndAsync();
            }
            
            return JsonSerializer.Deserialize<T>(decrypted) 
                ?? throw new InvalidOperationException("Failed to deserialize decrypted data");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt data from client");
            throw;
        }
    }

    public async Task<byte[]> EncryptForService<T>(T data, string serviceId)
    {
        try
        {
            var publicKey = await _keyManager.GetPublicKeyForService(serviceId);
            var serialized = JsonSerializer.Serialize(data);
            
            using var aes = Aes.Create();
            aes.KeySize = _options.KeySize;
            aes.GenerateKey();
            aes.GenerateIV();
            
            byte[] encryptedData;
            using (var encryptor = aes.CreateEncryptor())
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (var writer = new StreamWriter(cryptoStream))
                {
                    writer.Write(serialized);
                }
                
                encryptedData = memoryStream.ToArray();
            }
            
            byte[] encryptedKey;
            using (var rsa = RSA.Create())
            {
                if (publicKey.Contains("-----BEGIN PUBLIC KEY-----"))
                {
                    rsa.ImportFromPem(publicKey);
                }
                else
                {
                    rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
                }
                
                encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
            }
            
            var keyPair = await _keyManager.GetCurrentServiceKeys();
            var signature = SignData(Encoding.UTF8.GetBytes(serialized));
            
            var message = new EncryptedMessage
            {
                SenderServiceId = await _keyManager.GetCurrentServiceId(),
                RecipientServiceId = serviceId,
                EncryptedKey = Convert.ToBase64String(encryptedKey),
                Iv = Convert.ToBase64String(aes.IV),
                EncryptedData = Convert.ToBase64String(encryptedData),
                Signature = signature,
                ContentType = typeof(T).FullName ?? typeof(T).Name
            };
            
            return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to encrypt data for service {ServiceId}", serviceId);
            throw;
        }
    }

    public async Task<T> DecryptFromService<T>(byte[] encryptedData)
    {
        try
        {
            var messageJson = Encoding.UTF8.GetString(encryptedData);
            var message = JsonSerializer.Deserialize<EncryptedMessage>(messageJson)
                ?? throw new InvalidOperationException("Invalid encrypted message format");
            
            var keyPair = await _keyManager.GetCurrentServiceKeys();
            
            byte[] encryptedKeyBytes = Convert.FromBase64String(message.EncryptedKey);
            byte[] ivBytes = Convert.FromBase64String(message.Iv);
            byte[] dataBytes = Convert.FromBase64String(message.EncryptedData);
            
            byte[] decryptedKey;
            using (var rsa = RSA.Create())
            {
                rsa.ImportFromPem(keyPair.PrivateKey);
                decryptedKey = rsa.Decrypt(encryptedKeyBytes, RSAEncryptionPadding.OaepSHA256);
            }
            
            string decrypted;
            using (var aes = Aes.Create())
            {
                aes.Key = decryptedKey;
                aes.IV = ivBytes;
                
                using var decryptor = aes.CreateDecryptor();
                using var memoryStream = new MemoryStream(dataBytes);
                using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                using var reader = new StreamReader(cryptoStream);
                
                decrypted = reader.ReadToEnd();
            }
            
            return JsonSerializer.Deserialize<T>(decrypted)
                ?? throw new InvalidOperationException("Failed to deserialize decrypted data");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt service message");
            throw;
        }
    }

    public string SignData(byte[] data)
    {
        try
        {
            using var rsa = RSA.Create();
            var keyPair = _keyManager.GetCurrentServiceKeys().GetAwaiter().GetResult();
            rsa.ImportFromPem(keyPair.PrivateKey);
            
            byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to sign data");
            throw;
        }
    }

    public bool VerifySignature(byte[] data, string signature, string publicKey)
    {
        try
        {
            using var rsa = RSA.Create();
            
            if (publicKey.Contains("-----BEGIN PUBLIC KEY-----"))
            {
                rsa.ImportFromPem(publicKey);
            }
            else
            {
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);
            }
            
            byte[] signatureBytes = Convert.FromBase64String(signature);
            return rsa.VerifyData(data, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify signature");
            return false;
        }
    }
}