using CRM.Security.Encryption;
using CRM.Security.KeyManagement;
using CRM.Security.Messaging;
using CRM.Security.Messaging.RabbitMQ;
using CRM.Security.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CRM.Security;

public static class DependencyInjection
{
    public static IServiceCollection AddCrmSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<EncryptionOptions>(configuration.GetSection("Security:Encryption"));
        services.Configure<KeyManagementOptions>(configuration.GetSection("Security:KeyManagement"));
        
        services.AddSingleton<IKeyManager, FileSystemKeyManager>();
        services.AddSingleton<IEncryptionService, EncryptionService>();
        
        return services;
    }
    
    public static IServiceCollection AddEncryptedMessaging(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<MessagingOptions>(configuration.GetSection("Security:Messaging"));
        services.Configure<RabbitMQOptions>(configuration.GetSection("RabbitMQ"));

        services.AddSingleton<IEncryptedMessagePublisher, RabbitMQEncryptedMessagePublisher>();
        services.AddSingleton<IEncryptedMessageConsumer, RabbitMQEncryptedMessageConsumer>();
        
        return services;
    }
}