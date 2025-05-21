using CRM.Security.KeyManagement.Models;

namespace CRM.Security.KeyManagement;

public interface IKeyManager
{
    Task<KeyPair> GetCurrentServiceKeys();
    Task<string> GetPublicKeyForService(string serviceId);
    Task<string> GetCurrentServiceId();
    Task<KeyInfo?> GetCurrentKeyInfo();
    Task RotateKeys(TimeSpan? validity = null);
    Task RevokeKey(string keyId);
    Task<bool> ValidateKey(string keyId);
}