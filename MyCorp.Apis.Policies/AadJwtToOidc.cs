using Azure.ApiManagement.PolicyToolkit.Authoring;
using Azure.ApiManagement.PolicyToolkit.Authoring.Expressions;
using Newtonsoft.Json.Linq;

namespace MyCorp.Apis.Policies;

[Document]
public class AadJwtToOidc : IDocument
{
    public void Inbound(IInboundContext context)
    {
        context.CacheLookupValue(
            new CacheLookupValueConfig
            {
                Key = "cachedToken",
                VariableName = "successCachedToken",
                CachingType = "internal"
            }
        );

        if(IsCachedTokenValid(context.ExpressionContext))
        {
            context.SetHeader("Authorization", GetCachedToken(context.ExpressionContext));
        }
        else if (IsScopeSet(context.ExpressionContext))
        {
            context.SetVariable("requestBody", SetRequestBodyForScope(context.ExpressionContext));
        }
        else if (IsRefreshTokenSet(context.ExpressionContext))
        {
            context.SetVariable("requestBody", SetRequestBodyForRefreshToken(context.ExpressionContext));
        }
        else if (IsOtherTokenSet(context.ExpressionContext))
        {
            context.SetVariable("requestBody", SetRequestBodyForOtherToken(context.ExpressionContext));
        }
        else
        {
            context.InlinePolicy(
                "<trace source=\"trace-name\" severity=\"error\"> <message>Missing variables in policy</message> </trace>"
            );
            context.ReturnResponse(
                new ReturnResponseConfig
                {
                    Status = new StatusConfig
                    {
                        Code = 500,
                        Reason = "Internal Server error"
                    },
                    Body = new BodyConfig
                    {
                        Content = "Internal Server error, please contact your admin"
                    }
                }
            );
        }

        context.SendRequest(
            new SendRequestConfig
            {
                ResponseVariableName = "accessTokenResponse",
                Mode = "new",
                Timeout = GetPolicyTimeout(context.ExpressionContext),
                IgnoreError = false,
                Url = "@((string)context.Variables[\"oidcUrl\"])",
                Method = "POST",
                Headers = new[] {
                    new HeaderConfig
                    {
                        Name = "Content-Type",
                        ExistsAction = "override",
                        Values = new[] { "application/x-www-form-urlencoded" }
                    }
                },
                Body = new BodyConfig
                {
                    Content = "@((string)context.Variables[\"requestBody\"])"
                }
            }
        );

        if (IsAccessTokenResponseSuccessful(context.ExpressionContext))
        {
            context.SetVariable("accessTokenResponseBody", GetAccessTokenResponseBody(context.ExpressionContext));
            context.SetVariable("bearerToken", GetBearerToken(context.ExpressionContext));
            context.CacheStoreValue(
                new CacheStoreValueConfig
                {
                    Key = "cachedToken",
                    Value = GetBearerToken(context.ExpressionContext),
                    Duration = 3600,
                    CachingType = "internal"
                }
            );
            context.SetHeader("Authorization", GetAuthorizationHeader(context.ExpressionContext));
        }
        else
        {
            context.InlinePolicy("<trace source=\"trace-name\" severity=\"error\"> <message>TODO</message> </trace>" );
            context.ReturnResponse(
                new ReturnResponseConfig
                {
                    Status = new StatusConfig { Code = 401, Reason = "Unauthorized" },
                    Body = new BodyConfig
                    {
                        Content = "@(((IResponse)context.Variables[\"accessTokenResponse\"]).Body.As<JObject>(preserveContent: true).ToString())"
                    }
                }
            );
        }
    }

    public static bool IsCachedTokenValid(IExpressionContext context)
        => context.Variables.ContainsKey("successCachedToken");

    public static string GetCachedToken(IExpressionContext context)
        => "Bearer " + (string)context.Variables["cachedToken"];

    public static bool IsScopeSet(IExpressionContext context)
        => context.Variables.ContainsKey("oidcClientId") &&
           context.Variables.ContainsKey("oidcClientSecret") &&
           context.Variables.ContainsKey("oidcGrantType") &&
           context.Variables.ContainsKey("oidcScope");

    public static string SetRequestBodyForScope(IExpressionContext context)
        => "client_id=" + (string)context.Variables["oidcClientId"] +
           "&client_secret=" + (string)context.Variables["oidcClientSecret"] +
           "&grant_type=" + (string)context.Variables["oidcGrantType"] +
           "&scope=" + (string)context.Variables["oidcScope"];

    public static bool IsRefreshTokenSet(IExpressionContext context)
        => context.Variables.ContainsKey("oidcClientId") &&
           context.Variables.ContainsKey("oidcClientSecret") &&
           context.Variables.ContainsKey("oidcGrantType") &&
           context.Variables.ContainsKey("oidcRefreshToken");

    public static string SetRequestBodyForRefreshToken(IExpressionContext context)
        => "client_id=" + (string)context.Variables["oidcClientId"] +
           "&client_secret=" + (string)context.Variables["oidcClientSecret"] +
           "&grant_type=" + (string)context.Variables["oidcGrantType"] +
           "&refresh_token=" + (string)context.Variables["oidcRefreshToken"];

    public static bool IsOtherTokenSet(IExpressionContext context)
        => context.Variables.ContainsKey("oidcClientId") &&
           context.Variables.ContainsKey("oidcClientSecret") &&
           context.Variables.ContainsKey("oidcGrantType");

    public static string SetRequestBodyForOtherToken(IExpressionContext context)
        => "client_id=" + (string)context.Variables["oidcClientId"] +
           "&client_secret=" + (string)context.Variables["oidcClientSecret"] +
           "&grant_type=" + (string)context.Variables["oidcGrantType"];

    public static bool IsAccessTokenResponseSuccessful(IExpressionContext context)
        => ((IResponse)context.Variables["accessTokenResponse"]).StatusCode == 200;

    public static JObject GetAccessTokenResponseBody(IExpressionContext context)
        => ((IResponse)context.Variables["accessTokenResponse"]).Body.As<JObject>();

    public static string GetBearerToken(IExpressionContext context)
        => (string)((JObject)context.Variables["accessTokenResponseBody"])["access_token"];

    public static string GetAuthorizationHeader(IExpressionContext context)
        => "Bearer " + (string)context.Variables["bearerToken"];

    public static int GetPolicyTimeout(IExpressionContext context)
        => context.Variables.ContainsKey("policy-timeout") 
            ? Convert.ToInt32(context.Variables["policy-timeout"]) 
            : 30000;
}
