namespace CRM.Security.Options;

public class EncryptionOptions
{
    public string DefaultAlgorithm { get; set; } = "AES256";
    public int KeySize { get; set; } = 256;
    public bool UseCompression { get; set; } = true;
    public string DefaultPublicKeyFormat { get; set; } = "PEM";
}