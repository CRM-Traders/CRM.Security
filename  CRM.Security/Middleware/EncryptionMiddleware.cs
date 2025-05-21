using System.Text;
using System.Text.Json;
using CRM.Security.Encryption;
using CRM.Security.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace CRM.Security.Middleware;

public class EncryptionMiddleware(
    RequestDelegate next,
    IEncryptionService encryptionService,
    IKeyManager keyManager,
    ILogger<EncryptionMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        if (IsEncryptedRequest(context.Request))
        {
            await ProcessEncryptedRequest(context);
        }
        else
        {
            await next(context);
        }
    }

    private bool IsEncryptedRequest(HttpRequest request)
    {
        return request.Headers.ContainsKey("X-Encrypted") ||
               request.Headers.ContainsKey("X-Encryption-Version");
    }

    private async Task ProcessEncryptedRequest(HttpContext context)
    {
        try
        {
            context.Request.EnableBuffering();

            using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
            var encryptedBody = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;

            if (string.IsNullOrEmpty(encryptedBody))
            {
                await next(context);
                return;
            }

            var keyPair = await keyManager.GetCurrentServiceKeys();

            var decryptedObject = await encryptionService.DecryptFromClient<object>(
                encryptedBody,
                keyPair.PrivateKey);

            var decryptedJson = JsonSerializer.Serialize(decryptedObject);
            var decryptedBytes = Encoding.UTF8.GetBytes(decryptedJson);

            var originalBody = context.Request.Body;
            context.Request.Body = new MemoryStream(decryptedBytes);
            context.Request.ContentLength = decryptedBytes.Length;

            context.Items["WasEncrypted"] = true;

            var originalResponseBody = context.Response.Body;
            using var responseBody = new MemoryStream();
            context.Response.Body = responseBody;

            await next(context);

            if (context.Items.ContainsKey("WasEncrypted") &&
                context.Response.StatusCode == StatusCodes.Status200OK)
            {
                responseBody.Seek(0, SeekOrigin.Begin);
                var responseContent = await new StreamReader(responseBody).ReadToEndAsync();

                var clientPublicKey = context.Request.Headers["X-Client-Public-Key"].ToString();

                if (string.IsNullOrEmpty(clientPublicKey))
                {
                    clientPublicKey = keyPair.PublicKey;
                }

                var encryptedResponse = await encryptionService.EncryptForClient(
                    JsonSerializer.Deserialize<object>(responseContent),
                    clientPublicKey);

                var encryptedBytes = Encoding.UTF8.GetBytes(encryptedResponse);

                context.Response.Headers.Add("X-Encrypted", "true");
                context.Response.Headers.Add("X-Encryption-Version", "1.0");
                context.Response.ContentLength = encryptedBytes.Length;
                context.Response.ContentType = "application/json";

                responseBody.SetLength(0);
                await responseBody.WriteAsync(encryptedBytes, 0, encryptedBytes.Length);
                responseBody.Seek(0, SeekOrigin.Begin);
            }

            await responseBody.CopyToAsync(originalResponseBody);
            context.Response.Body = originalResponseBody;
            context.Request.Body = originalBody;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error processing encrypted request");

            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";

            var error = new
            {
                error = "Failed to process encrypted request",
                message = ex.Message
            };

            await context.Response.WriteAsync(JsonSerializer.Serialize(error));
        }
    }
}