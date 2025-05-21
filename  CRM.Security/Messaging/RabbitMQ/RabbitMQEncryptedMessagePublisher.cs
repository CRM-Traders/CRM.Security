using System.Text;
using System.Text.Json;
using CRM.Security.Encryption;
using CRM.Security.KeyManagement;
using CRM.Security.Messaging.RabbitMQ.Models;
using CRM.Security.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;

namespace CRM.Security.Messaging.RabbitMQ;

public class RabbitMQEncryptedMessagePublisher : IEncryptedMessagePublisher, IDisposable
{
    private readonly IEncryptionService _encryptionService;
    private readonly IKeyManager _keyManager;
    private readonly ILogger<RabbitMQEncryptedMessagePublisher> _logger;
    private readonly RabbitMQOptions _options;
    private readonly IConnection _connection;
    private readonly IModel _channel;

    public RabbitMQEncryptedMessagePublisher(
        IEncryptionService encryptionService,
        IKeyManager keyManager,
        IOptions<RabbitMQOptions> options,
        ILogger<RabbitMQEncryptedMessagePublisher> logger)
    {
        _encryptionService = encryptionService;
        _keyManager = keyManager;
        _logger = logger;
        _options = options.Value;

        var factory = new ConnectionFactory
        {
            HostName = _options.HostName,
            UserName = _options.UserName,
            Password = _options.Password,
            VirtualHost = _options.VirtualHost,
            Port = _options.Port
        };

        _connection = factory.CreateConnection();
        _channel = _connection.CreateModel();

        _channel.ExchangeDeclare(
            exchange: _options.ExchangeName,
            type: ExchangeType.Topic,
            durable: true,
            autoDelete: false);
    }

    public async Task PublishAsync<T>(string topic, T message, string targetServiceId)
    {
        try
        {
            var serviceId = await _keyManager.GetCurrentServiceId();

            var encryptedData = await _encryptionService.EncryptForService(message, targetServiceId);

            var envelope = new MessageEnvelope
            {
                ServiceId = serviceId,
                TargetServiceId = targetServiceId,
                Payload = Convert.ToBase64String(encryptedData)
            };

            var serializedEnvelope = JsonSerializer.Serialize(envelope);
            var body = Encoding.UTF8.GetBytes(serializedEnvelope);

            var routingKey = $"{topic}.{targetServiceId}";

            _channel.BasicPublish(
                exchange: _options.ExchangeName,
                routingKey: routingKey,
                basicProperties: null,
                body: body);

            _logger.LogDebug("Message published to {Topic} for service {ServiceId}",
                topic, targetServiceId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to publish message to {Topic} for service {ServiceId}",
                topic, targetServiceId);
            throw;
        }
    }

    public async Task PublishAsync<T>(string topic, T message, IEnumerable<string> targetServiceIds)
    {
        foreach (var serviceId in targetServiceIds)
        {
            await PublishAsync(topic, message, serviceId);
        }
    }

    public void Dispose()
    {
        _channel?.Dispose();
        _connection?.Dispose();
    }
}