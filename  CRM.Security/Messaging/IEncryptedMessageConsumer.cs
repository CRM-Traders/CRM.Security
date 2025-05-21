namespace CRM.Security.Messaging;

public interface IEncryptedMessageConsumer
{
    Task Subscribe<T>(string topic, Func<T, Task> handler);
    Task Subscribe<T>(string topic, Func<T, string, Task> handler);
    Task Unsubscribe(string topic);
}