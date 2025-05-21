using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using CRM.Security.Encryption;
using CRM.Security.KeyManagement;
using CRM.Security.Messaging.RabbitMQ.Models;
using CRM.Security.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace CRM.Security.Messaging.RabbitMQ;

public class RabbitMQEncryptedMessageConsumer : IEncryptedMessageConsumer, IDisposable
{
    private readonly IEncryptionService _encryptionService;
    private readonly IKeyManager _keyManager;
    private readonly ILogger<RabbitMQEncryptedMessageConsumer> _logger;
    private readonly RabbitMQOptions _options;
    private readonly IConnection _connection;
    private readonly IModel _channel;
    private readonly ConcurrentDictionary<string, string> _consumerTags = new();
    private readonly string _serviceId;

    public RabbitMQEncryptedMessageConsumer(
        IEncryptionService encryptionService,
        IKeyManager keyManager,
        IOptions<RabbitMQOptions> options,
        ILogger<RabbitMQEncryptedMessageConsumer> logger)
    {
        _encryptionService = encryptionService;
        _keyManager = keyManager;
        _logger = logger;
        _options = options.Value;
        _serviceId = _keyManager.GetCurrentServiceId().GetAwaiter().GetResult();

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

    public Task Subscribe<T>(string topic, Func<T, Task> handler)
    {
        return Subscribe<T>(topic, async (message, _) => await handler(message));
    }

    public Task Subscribe<T>(string topic, Func<T, string, Task> handler)
    {
        var queueName = $"{topic}_{_serviceId}_queue";

        _channel.QueueDeclare(
            queue: queueName,
            durable: true,
            exclusive: false,
            autoDelete: false);

        _channel.QueueBind(
            queue: queueName,
            exchange: _options.ExchangeName,
            routingKey: $"{topic}.{_serviceId}");

        var consumer = new AsyncEventingBasicConsumer(_channel);

        consumer.Received += async (model, ea) =>
        {
            try
            {
                var body = ea.Body.ToArray();
                var message = Encoding.UTF8.GetString(body);

                var envelope = JsonSerializer.Deserialize<MessageEnvelope>(message);

                if (envelope?.TargetServiceId != _serviceId)
                {
                    _logger.LogWarning("Received message for service {ServiceId}, but this service is {ThisServiceId}",
                        envelope?.TargetServiceId, _serviceId);
                    return;
                }

                var payloadBytes = Convert.FromBase64String(envelope.Payload);
                var decryptedMessage = await _encryptionService.DecryptFromService<T>(payloadBytes);

                await handler(decryptedMessage, envelope.ServiceId);

                _channel.BasicAck(ea.DeliveryTag, false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing message from topic {Topic}", topic);
                _channel.BasicNack(ea.DeliveryTag, false, true);
            }
        };

        var consumerTag = _channel.BasicConsume(
            queue: queueName,
            autoAck: false,
            consumer: consumer);

        _consumerTags[topic] = consumerTag;

        _logger.LogInformation("Subscribed to topic {Topic}", topic);

        return Task.CompletedTask;
    }

    public Task Unsubscribe(string topic)
    {
        if (_consumerTags.TryRemove(topic, out var consumerTag))
        {
            _channel.BasicCancel(consumerTag);
            _logger.LogInformation("Unsubscribed from topic {Topic}", topic);
        }

        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _channel?.Dispose();
        _connection?.Dispose();
    }
}