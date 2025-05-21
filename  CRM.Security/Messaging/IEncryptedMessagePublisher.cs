namespace CRM.Security.Messaging;

public interface IEncryptedMessagePublisher
{
    Task PublishAsync<T>(string topic, T message, string targetServiceId);
    Task PublishAsync<T>(string topic, T message, IEnumerable<string> targetServiceIds);
}