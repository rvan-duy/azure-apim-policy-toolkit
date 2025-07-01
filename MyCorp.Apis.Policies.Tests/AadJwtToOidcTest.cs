using MyCorp.Apis.Policies;

using Azure.ApiManagement.PolicyToolkit.Testing.Expressions;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;

namespace MyCorp.Apis.Policies.Tests;

[TestClass]
public class AadJwtToOidcTest
{
    #region Decision Logic Tests

    [TestMethod]
    public void Should_Use_Cached_Token_When_Valid()
    {
        var context = new MockExpressionContext();

        context.Variables["successCachedToken"] = "very-secret-token";

        Assert.IsTrue(AadJwtToOidc.IsCachedTokenValid(context));
    }

    [TestMethod]
    public void Should_Use_Scope_When_Cached_Token_Is_Invalid_And_Scope_Is_Set()
    {
        var context = new MockExpressionContext();

        context.Variables["oidcScope"] = "test-scope";
        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcClientSecret"] = "test-client-secret";
        context.Variables["oidcGrantType"] = "client_credentials";
        context.Variables["oidcUrl"] = "https://test.oidc.com";

        Assert.IsTrue(AadJwtToOidc.IsScopeSet(context));
        Assert.IsFalse(AadJwtToOidc.IsCachedTokenValid(context));
        Assert.IsFalse(AadJwtToOidc.IsRefreshTokenSet(context));
    }

    [TestMethod]
    public void Should_Use_Refresh_Token_When_Cached_Token_Is_Invalid_And_Refresh_Token_Is_Set()
    {
        var context = new MockExpressionContext();
        
        context.Variables["oidcRefreshToken"] = "test-refresh-token";
        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcClientSecret"] = "test-client-secret";
        context.Variables["oidcGrantType"] = "client_credentials";
        context.Variables["oidcUrl"] = "https://test.oidc.com";

        Assert.IsTrue(AadJwtToOidc.IsRefreshTokenSet(context));
        Assert.IsFalse(AadJwtToOidc.IsCachedTokenValid(context));
        Assert.IsFalse(AadJwtToOidc.IsScopeSet(context));
    }

    [TestMethod]
    public void Should_Use_Other_Token_When_Cached_Token_Is_Invalid_And_Defaults_To_Other_Token()
    {
        var context = new MockExpressionContext();
        
        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcClientSecret"] = "test-client-secret";
        context.Variables["oidcGrantType"] = "client_credentials";
        context.Variables["oidcUrl"] = "https://test.oidc.com";

        Assert.IsTrue(AadJwtToOidc.IsOtherTokenSet(context));
        Assert.IsFalse(AadJwtToOidc.IsCachedTokenValid(context));
        Assert.IsFalse(AadJwtToOidc.IsScopeSet(context));
        Assert.IsFalse(AadJwtToOidc.IsRefreshTokenSet(context));
    }

    [TestMethod]
    public void Should_Return_False_When_Cached_Token_Is_Invalid_And_No_Other_Token_Is_Set()
    {
        var context = new MockExpressionContext();

        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcUrl"] = "https://test.oidc.com";

        Assert.IsFalse(AadJwtToOidc.IsCachedTokenValid(context));
        Assert.IsFalse(AadJwtToOidc.IsScopeSet(context));
        Assert.IsFalse(AadJwtToOidc.IsRefreshTokenSet(context));
        Assert.IsFalse(AadJwtToOidc.IsOtherTokenSet(context));
    }

    [TestMethod]
    public void Should_Not_Use_Cached_Token_When_Cached_Token_Is_Invalid()
    {
        var context = new MockExpressionContext();
        
        context.Variables["cachedToken"] = "test-token";
        context.Variables["cachedTokenExpiration"] = DateTime.UtcNow.AddHours(-1).ToString();

        Assert.IsFalse(AadJwtToOidc.IsCachedTokenValid(context));
        Assert.IsFalse(AadJwtToOidc.IsScopeSet(context));
        Assert.IsFalse(AadJwtToOidc.IsRefreshTokenSet(context));
        Assert.IsFalse(AadJwtToOidc.IsOtherTokenSet(context));
    }

    [TestMethod]
    public void Should_Not_Use_Cached_Token_But_Use_Scope_When_Cached_Token_Is_Invalid_And_Scope_Is_Set()
    {
        var context = new MockExpressionContext();
        
        context.Variables["cachedToken"] = "test-token";
        context.Variables["cachedTokenExpiration"] = DateTime.UtcNow.AddHours(-1).ToString();
        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcClientSecret"] = "test-client-secret";
        context.Variables["oidcGrantType"] = "client_credentials";
        context.Variables["oidcUrl"] = "https://test.oidc.com";
        context.Variables["oidcScope"] = "test-scope";

        Assert.IsFalse(AadJwtToOidc.IsCachedTokenValid(context));
        Assert.IsTrue(AadJwtToOidc.IsScopeSet(context));
        Assert.IsFalse(AadJwtToOidc.IsRefreshTokenSet(context));
    }

    #endregion

    #region Request Body Formatting Tests

    [TestMethod]
    public void Should_Format_Request_Body_For_Scope_Correctly()
    {
        var context = new MockExpressionContext();
        
        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcClientSecret"] = "test-client-secret";
        context.Variables["oidcGrantType"] = "client_credentials";
        context.Variables["oidcScope"] = "test-scope";

        var expectedRequestBody = "client_id=test-client-id&client_secret=test-client-secret&grant_type=client_credentials&scope=test-scope";
        var actualRequestBody = AadJwtToOidc.SetRequestBodyForScope(context);

        Assert.AreEqual(expectedRequestBody, actualRequestBody);
    }

    [TestMethod]
    public void Should_Format_Request_Body_For_Refresh_Token_Correctly()
    {
        var context = new MockExpressionContext();
        
        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcClientSecret"] = "test-client-secret";
        context.Variables["oidcGrantType"] = "client_credentials";
        context.Variables["oidcRefreshToken"] = "test-refresh-token";

        var expectedRequestBody = "client_id=test-client-id&client_secret=test-client-secret&grant_type=client_credentials&refresh_token=test-refresh-token";
        var actualRequestBody = AadJwtToOidc.SetRequestBodyForRefreshToken(context);

        Assert.AreEqual(expectedRequestBody, actualRequestBody);
    }

    [TestMethod]
    public void Should_Format_Request_Body_For_Other_Token_Correctly()
    {
        var context = new MockExpressionContext();
        
        context.Variables["oidcClientId"] = "test-client-id";
        context.Variables["oidcClientSecret"] = "test-client-secret";
        context.Variables["oidcGrantType"] = "client_credentials";

        var expectedRequestBody = "client_id=test-client-id&client_secret=test-client-secret&grant_type=client_credentials";
        var actualRequestBody = AadJwtToOidc.SetRequestBodyForOtherToken(context);

        Assert.AreEqual(expectedRequestBody, actualRequestBody);
    }

    #endregion

    #region Timeout Tests

    [TestMethod]
    public void Should_Use_Default_Policy_Timeout_When_Not_Set()
    {
        var context = new MockExpressionContext();

        var timeout = AadJwtToOidc.GetPolicyTimeout(context);
        Assert.AreEqual(30000, timeout);
    }

    [TestMethod]
    public void Should_Use_Custom_Policy_Timeout_When_Set()
    {
        var context = new MockExpressionContext();
        context.Variables["policy-timeout"] = 60000;

        var timeout = AadJwtToOidc.GetPolicyTimeout(context);
        Assert.AreEqual(60000, timeout);
    }

    #endregion
}
