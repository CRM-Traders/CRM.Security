namespace CRM.Security.Options;

public class MessagingOptions
{
    public bool EnableEncryption { get; set; } = true;
    public bool SignMessages { get; set; } = true;
    public string DefaultExchange { get; set; } = "crm_events";
}

public class RabbitMQOptions
{
    public string HostName { get; set; } = "localhost";
    public string UserName { get; set; } = "guest";
    public string Password { get; set; } = "guest";
    public string VirtualHost { get; set; } = "/";
    public int Port { get; set; } = 5672;
    public string ExchangeName { get; set; } = "event_exchange";
    public string QueueName { get; set; } = "event_store_queue";
    public string RoutingKeyPattern { get; set; } = "events.#";
}