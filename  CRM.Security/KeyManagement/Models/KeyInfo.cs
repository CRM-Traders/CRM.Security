namespace CRM.Security.KeyManagement.Models;

public class KeyInfo
{
    public string KeyId { get; set; } = string.Empty;
    public string ServiceId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public KeyStatus Status { get; set; } = KeyStatus.Active;
}

public enum KeyStatus
{
    Active,
    Backup,
    Revoked,
    Expired
}