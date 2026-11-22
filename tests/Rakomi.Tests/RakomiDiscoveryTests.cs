// SPDX-License-Identifier: MIT
using System;
using System.Net;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Rakomi.Tests;

public sealed class RakomiDiscoveryTests
{
    private const string Issuer = "https://api.rakomi.com";
    private const string ConfigUrl = "https://api.rakomi.com/.well-known/openid-configuration";
    private const string JwksUrl = "https://api.rakomi.com/.well-known/jwks.json";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    private static JsonObject Configuration() => new()
    {
        ["issuer"] = Issuer,
        ["authorization_endpoint"] = "https://accounts.rakomi.com/authorize",
        ["token_endpoint"] = "https://api.rakomi.com/oauth/token",
        ["userinfo_endpoint"] = "https://api.rakomi.com/oauth/userinfo",
        ["jwks_uri"] = JwksUrl,
        ["response_types_supported"] = new JsonArray("code"),
        ["subject_types_supported"] = new JsonArray("public"),
        ["id_token_signing_alg_values_supported"] = new JsonArray("RS256"),
        ["scopes_supported"] = new JsonArray("openid", "profile", "email"),
        ["code_challenge_methods_supported"] = new JsonArray("S256"),
    };

    private const string Jwks = """{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig","n":"AQAB","e":"AQAB"}]}""";

    private static Task<RakomiDiscoveryResult> Discover(FakeHandler handler, string issuer = Issuer, TimeSpan? timeout = null)
        => DiscoverWith(handler, issuer, timeout ?? Timeout, TestContext.Current.CancellationToken);

    private static async Task<RakomiDiscoveryResult> DiscoverWith(FakeHandler handler, string issuer, TimeSpan timeout, CancellationToken ct)
    {
        using HttpClient client = new(handler, disposeHandler: false);
        return await RakomiDiscovery.DiscoverAsync(new Uri(issuer), client, timeout, ct);
    }

    private static readonly string[] S256 = { "S256" };

    private static FakeHandler Valid(JsonObject? configuration = null, string jwks = Jwks)
        => new FakeHandler().Json(ConfigUrl, (configuration ?? Configuration()).ToJsonString()).Json(JwksUrl, jwks);

    [Fact]
    public async Task Discovers_metadata_and_keys()
    {
        FakeHandler handler = Valid();

        RakomiDiscoveryResult result = await Discover(handler);

        Assert.Equal(Issuer, result.Metadata.Issuer);
        Assert.Equal(new Uri("https://api.rakomi.com/oauth/token"), result.Metadata.TokenEndpoint);
        Assert.Equal(new Uri("https://accounts.rakomi.com/authorize"), result.Metadata.AuthorizationEndpoint);
        Assert.Equal(new Uri(JwksUrl), result.Metadata.JwksUri);
        Assert.Equal(new Uri("https://api.rakomi.com/oauth/userinfo"), result.Metadata.UserInfoEndpoint);
        Assert.Null(result.Metadata.EndSessionEndpoint);
        Assert.Equal(S256, result.Metadata.CodeChallengeMethodsSupported);
        Assert.Empty(result.Metadata.GrantTypesSupported);
        Assert.Equal("code", result.Metadata.Document.GetProperty("response_types_supported")[0].GetString());
        RakomiJsonWebKey key = Assert.Single(result.Keys.Keys);
        Assert.Equal("RSA", key.KeyType);
        Assert.Equal("k1", key.KeyId);
        Assert.Equal("RS256", key.Algorithm);
        Assert.Equal("sig", key.Use);
        Assert.Equal("AQAB", key.Exponent);
        Assert.Equal(new[] { new Uri(ConfigUrl), new Uri(JwksUrl) }, handler.Requests);
    }

    [Fact]
    public async Task Issuer_with_a_path_gets_the_well_known_suffix_after_the_path()
    {
        JsonObject configuration = Configuration();
        configuration["issuer"] = "https://id.example.com/tenant";
        FakeHandler handler = new FakeHandler()
            .Json("https://id.example.com/tenant/.well-known/openid-configuration", configuration.ToJsonString())
            .Json(JwksUrl, Jwks);

        RakomiDiscoveryResult result = await Discover(handler, "https://id.example.com/tenant");

        Assert.Equal("https://id.example.com/tenant", result.Metadata.Issuer);
    }

    [Theory]
    [InlineData("http://api.rakomi.com")]
    [InlineData("https://api.rakomi.com?x=1")]
    [InlineData("https://api.rakomi.com#f")]
    [InlineData("https://user@api.rakomi.com")]
    public async Task Refuses_an_issuer_that_is_not_plain_https(string issuer)
    {
        FakeHandler handler = Valid();

        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(handler, issuer));
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("https://evil.example.com")]
    [InlineData("https://api.rakomi.com/")]
    [InlineData("https://API.rakomi.com")]
    public async Task Refuses_a_document_naming_another_issuer(string documentIssuer)
    {
        JsonObject configuration = Configuration();
        configuration["issuer"] = documentIssuer;

        RakomiDiscoveryException ex = await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(Valid(configuration)));
        Assert.Contains("issuer", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("authorization_endpoint")]
    [InlineData("token_endpoint")]
    [InlineData("jwks_uri")]
    [InlineData("response_types_supported")]
    [InlineData("subject_types_supported")]
    [InlineData("id_token_signing_alg_values_supported")]
    public async Task Refuses_a_document_without_a_required_member(string member)
    {
        JsonObject configuration = Configuration();
        configuration.Remove(member);

        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(Valid(configuration)));
    }

    [Fact]
    public async Task Refuses_an_empty_required_array()
    {
        JsonObject configuration = Configuration();
        configuration["subject_types_supported"] = new JsonArray();

        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(Valid(configuration)));
    }

    [Theory]
    [InlineData("jwks_uri", "http://api.rakomi.com/.well-known/jwks.json")]
    [InlineData("token_endpoint", "http://api.rakomi.com/oauth/token")]
    [InlineData("userinfo_endpoint", "http://api.rakomi.com/oauth/userinfo")]
    [InlineData("authorization_endpoint", "/authorize")]
    public async Task Refuses_a_published_url_that_is_not_absolute_https(string member, string value)
    {
        JsonObject configuration = Configuration();
        configuration[member] = value;
        FakeHandler handler = Valid(configuration);

        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(handler));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Refuses_a_member_of_the_wrong_type()
    {
        JsonObject configuration = Configuration();
        configuration["response_types_supported"] = "code";

        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(Valid(configuration)));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.Found)]
    public async Task Refuses_a_non_success_response(HttpStatusCode status)
    {
        FakeHandler handler = new FakeHandler().Json(ConfigUrl, "{}", status);

        RakomiDiscoveryException ex = await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(handler));
        Assert.Equal(status, ex.StatusCode);
    }

    [Fact]
    public async Task Refuses_a_response_that_ended_on_http()
    {
        FakeHandler handler = new FakeHandler().Route(ConfigUrl, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, "http://api.rakomi.com/.well-known/openid-configuration"),
            Content = new StringContent(Configuration().ToJsonString()),
        }));

        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(handler));
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("[]")]
    public async Task Refuses_a_document_that_is_not_a_json_object(string body)
    {
        FakeHandler handler = new FakeHandler().Json(ConfigUrl, body);

        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(handler));
    }

    [Fact]
    public async Task Refuses_a_document_over_the_size_limit()
    {
        string big = "{\"pad\":\"" + new string('a', RakomiDiscovery.MaxDocumentBytes) + "\"}";
        FakeHandler handler = new FakeHandler().Json(ConfigUrl, big);

        RakomiDiscoveryException ex = await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(handler));
        Assert.Contains("larger", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"keys":[]}""")]
    [InlineData("""{"keys":[{"kid":"k1"}]}""")]
    [InlineData("""{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}]}""")]
    [InlineData("""{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}""")]
    [InlineData("""{"keys":["x"]}""")]
    public async Task Refuses_an_invalid_key_set(string jwks)
    {
        await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(Valid(jwks: jwks)));
    }

    [Fact]
    public async Task Times_out()
    {
        FakeHandler handler = new FakeHandler().Route(ConfigUrl, async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            throw new InvalidOperationException("unreachable");
        });

        RakomiDiscoveryException ex = await Assert.ThrowsAsync<RakomiDiscoveryException>(
            () => Discover(handler, timeout: TimeSpan.FromMilliseconds(100)));
        Assert.Contains("timed out", ex.Message, StringComparison.Ordinal);
        Assert.IsAssignableFrom<OperationCanceledException>(ex.InnerException);
    }

    [Fact]
    public async Task Caller_cancellation_surfaces_as_cancellation()
    {
        using CancellationTokenSource cts = new();
        FakeHandler handler = new FakeHandler().Route(ConfigUrl, async (_, ct) =>
        {
            await cts.CancelAsync();
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            throw new InvalidOperationException("unreachable");
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DiscoverWith(handler, Issuer, Timeout, cts.Token));
    }

    [Fact]
    public async Task Refuses_a_non_positive_timeout()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => Discover(Valid(), timeout: TimeSpan.Zero));
    }

    [Fact]
    public async Task Request_failure_is_a_discovery_exception()
    {
        FakeHandler handler = new FakeHandler().Route(ConfigUrl, (_, _) => throw new HttpRequestException("connection refused"));

        RakomiDiscoveryException ex = await Assert.ThrowsAsync<RakomiDiscoveryException>(() => Discover(handler));
        Assert.IsType<HttpRequestException>(ex.InnerException);
    }
}
