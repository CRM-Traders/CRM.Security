namespace CRM.Security.Encryption;

public interface IEncryptionService
{
    Task<string> EncryptForClient<T>(T data, string publicKey);
    Task<T> DecryptFromClient<T>(string encryptedData, string privateKey);
    
    Task<byte[]> EncryptForService<T>(T data, string serviceId);
    Task<T> DecryptFromService<T>(byte[] encryptedData);
    
    string SignData(byte[] data);
    bool VerifySignature(byte[] data, string signature, string publicKey);
}