namespace CRM.Security.Encryption.Models;

public class EncryptedPackage
{
    public string Key { get; set; } = string.Empty;
    public string Iv { get; set; } = string.Empty;
    public string Data { get; set; } = string.Empty;
    public string Algorithm { get; set; } = "AES256_RSA";
    public string Version { get; set; } = "1.0";
    public string Signature { get; set; } = string.Empty;
    public bool Compressed { get; set; } = false;
}