using CRM.Security.Messaging.RabbitMQ;
using CRM.Security.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CRM.Security.Messaging.Common;

public static class MessageBrokerExtensions
{
    public static IServiceCollection AddRabbitMQEncryptedMessaging(this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<RabbitMQOptions>(configuration.GetSection("RabbitMQ"));

        services.AddSingleton<IEncryptedMessagePublisher, RabbitMQEncryptedMessagePublisher>();
        services.AddSingleton<IEncryptedMessageConsumer, RabbitMQEncryptedMessageConsumer>();

        return services;
    }
}