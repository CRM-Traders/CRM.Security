namespace CRM.Security.Messaging.RabbitMQ.Models;

public class MessageEnvelope
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString();
    public string ServiceId { get; set; } = string.Empty;
    public string TargetServiceId { get; set; } = string.Empty;
    public string EncryptionVersion { get; set; } = "1.0";
    public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public string Payload { get; set; } = string.Empty;
}