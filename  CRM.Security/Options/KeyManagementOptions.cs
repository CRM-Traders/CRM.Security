namespace CRM.Security.Options;

public class KeyManagementOptions
{
    public string KeysPath { get; set; } = "/opt/crm/keys";
    public int KeyRotationDays { get; set; } = 30;
    public int MinKeyAge { get; set; } = 7;
    public string ServiceId { get; set; } = "default-service";
    public bool CreateDirectoryIfNotExists { get; set; } = true;
    public bool SetSecurePermissions { get; set; } = true;
}