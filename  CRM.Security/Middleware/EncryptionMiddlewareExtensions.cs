using Microsoft.AspNetCore.Builder;

namespace CRM.Security.Middleware;

public static class EncryptionMiddlewareExtensions
{
    public static IApplicationBuilder UseEncryption(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<EncryptionMiddleware>();
    }
}