using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Primitives;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JWTClaimsPrincipleImplementation.CustomFilter
{
    public sealed class IdempotentAttribute: Attribute, IAsyncActionFilter
    {
        public const int DefaultCacheDuration = 60; // Default cache duration in seconds
        public readonly TimeSpan _cacheDuration;
        public IdempotentAttribute(int cacheDurationInMinutes = DefaultCacheDuration)
        {
           _cacheDuration = TimeSpan.FromMinutes(cacheDurationInMinutes);
        }
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if(!context.HttpContext.Request.Headers.TryGetValue("Idempotence-Key",out StringValues idempotenceKeyValue)
                || !Guid.TryParse(idempotenceKeyValue, out Guid idempotenceKey))
            {
                context.Result = new BadRequestObjectResult("Idempotence-Key header is required.");
                return;
            }
            IDistributedCache cache = context.HttpContext
            .RequestServices.GetRequiredService<IDistributedCache>();

            // Check if we already processed this request and return a cached response (if it exists)
            string cacheKey = $"Idempotent_{idempotenceKey}";
            var cachedResponse = await cache.GetStringAsync(cacheKey);
            if (cachedResponse is not null)
            {
                IdempotentResponse response = JsonSerializer.Deserialize<IdempotentResponse>(cachedResponse)!;
                context.Result = new ObjectResult(response.Value)
                {
                    StatusCode = response.StatusCode // Use the cached status code
                };
                return;
            }
            ActionExecutedContext actionExecutedContext = await next();
            if(actionExecutedContext.Result is ObjectResult { StatusCode: >= 200 and <300} objectResult)
            {
                int statusCode = objectResult.StatusCode ?? StatusCodes.Status200OK; // Default to 200 if not set
                IdempotentResponse idempotentResponse = new IdempotentResponse(statusCode, objectResult.Value);

                await cache.SetStringAsync(cacheKey,JsonSerializer.Serialize(idempotentResponse), 
                    new DistributedCacheEntryOptions
                    {
                        AbsoluteExpirationRelativeToNow = _cacheDuration
                    });
            }
            throw new NotImplementedException();
        }
    }
    internal sealed class IdempotentResponse
    {
        [JsonConstructor]
        public IdempotentResponse(int statusCode, object? value)
        {
            StatusCode = statusCode;
            Value = value;
        }
        public int StatusCode { get; }
        public object? Value { get; }
    }
}
