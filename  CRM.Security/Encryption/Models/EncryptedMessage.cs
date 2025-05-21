namespace CRM.Security.Encryption.Models;

public class EncryptedMessage
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString();
    public string SenderServiceId { get; set; } = string.Empty;
    public string RecipientServiceId { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public string EncryptedKey { get; set; } = string.Empty;
    public string Iv { get; set; } = string.Empty;
    public string EncryptedData { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public string Algorithm { get; set; } = "AES256_RSA";
    public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
}