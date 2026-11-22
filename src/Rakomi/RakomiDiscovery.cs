// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Rakomi;

/// <summary>
/// OpenID Connect discovery (OpenID Connect Discovery 1.0, RFC 8414) for a Rakomi issuer such as
/// <c>https://api.rakomi.com</c>.
/// </summary>
/// <remarks>
/// Discovery fetches <c>{issuer}/.well-known/openid-configuration</c>, checks that its <c>issuer</c> member is
/// equal to the issuer it was called with, that the required members are present and that every published URL
/// is an absolute HTTPS URL, then fetches the JSON Web Key Set at <c>jwks_uri</c>. Only HTTPS is used, a
/// response may not redirect, a document may be at most 1 MiB, and the whole call has a timeout.
/// </remarks>
public static class RakomiDiscovery
{
    /// <summary>The timeout of a whole discovery call unless one is given: 10 seconds.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);

    internal const int MaxDocumentBytes = 1024 * 1024;

    private const string WellKnownPath = "/.well-known/openid-configuration";

    private static readonly string[] PrivateKeyMembers = { "d", "p", "q", "dp", "dq", "qi", "k" };

    private static readonly Lazy<HttpClient> SharedClient = new(() =>
        new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        })
        {
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        });

    /// <summary>
    /// Discovers the provider metadata and the JSON Web Key Set of <paramref name="issuer"/> with a shared
    /// <see cref="HttpClient"/> that does not follow redirects, and <see cref="DefaultTimeout"/>.
    /// </summary>
    /// <param name="issuer">The issuer, for example <c>https://api.rakomi.com</c>. It must be an absolute HTTPS URL
    /// without a query or fragment, and the document's <c>issuer</c> must equal it exactly.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="ArgumentNullException"><paramref name="issuer"/> is null.</exception>
    /// <exception cref="RakomiDiscoveryException">Discovery failed or a document did not validate.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public static Task<RakomiDiscoveryResult> DiscoverAsync(Uri issuer, CancellationToken cancellationToken = default)
        => DiscoverAsync(issuer, SharedClient.Value, DefaultTimeout, cancellationToken);

    /// <summary>
    /// Discovers the provider metadata and the JSON Web Key Set of <paramref name="issuer"/> with the given
    /// <see cref="HttpClient"/> and timeout.
    /// </summary>
    /// <param name="issuer">The issuer, for example <c>https://api.rakomi.com</c>. It must be an absolute HTTPS URL
    /// without a query or fragment, and the document's <c>issuer</c> must equal it exactly.</param>
    /// <param name="httpClient">The client the requests go through. A response whose final URL is not HTTPS is
    /// refused, whatever the client's redirect setting.</param>
    /// <param name="timeout">The timeout of the whole call (both requests); must be positive.</param>
    /// <param name="cancellationToken">Cancels the call.</param>
    /// <exception cref="ArgumentNullException"><paramref name="issuer"/> or <paramref name="httpClient"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="timeout"/> is not positive.</exception>
    /// <exception cref="RakomiDiscoveryException">Discovery failed or a document did not validate.</exception>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
    public static async Task<RakomiDiscoveryResult> DiscoverAsync(
        Uri issuer,
        HttpClient httpClient,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        ArgumentNullException.ThrowIfNull(httpClient);
        if (timeout <= TimeSpan.Zero && timeout != System.Threading.Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), timeout, "The timeout must be positive.");
        }

        string expectedIssuer = ValidateIssuer(issuer);
        Uri configurationUri = new(expectedIssuer.TrimEnd('/') + WellKnownPath, UriKind.Absolute);

        using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            using JsonDocument configuration = await GetJsonAsync(httpClient, configurationUri, timeoutSource.Token).ConfigureAwait(false);
            RakomiProviderMetadata metadata = ParseMetadata(configuration.RootElement, expectedIssuer);

            using JsonDocument jwks = await GetJsonAsync(httpClient, metadata.JwksUri, timeoutSource.Token).ConfigureAwait(false);
            RakomiJsonWebKeySet keys = ParseKeySet(jwks.RootElement);

            return new RakomiDiscoveryResult(metadata, keys);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new RakomiDiscoveryException($"Discovery of {expectedIssuer} timed out after {timeout.TotalSeconds:0.###} s.", ex);
        }
    }

    private static string ValidateIssuer(Uri issuer)
    {
        if (!issuer.IsAbsoluteUri || issuer.Scheme != Uri.UriSchemeHttps)
        {
            throw new RakomiDiscoveryException("The issuer must be an absolute HTTPS URL.");
        }

        if (issuer.Query.Length > 0 || issuer.Fragment.Length > 0 || issuer.UserInfo.Length > 0)
        {
            throw new RakomiDiscoveryException("The issuer must not have a query, a fragment or user information.");
        }

        return issuer.OriginalString;
    }

    private static async Task<JsonDocument> GetJsonAsync(HttpClient httpClient, Uri uri, CancellationToken cancellationToken)
    {
        RequireHttps(uri, "request URL");

        using HttpRequestMessage request = new(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        HttpResponseMessage response;
        try
        {
            response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new RakomiDiscoveryException($"The request to {uri} failed.", ex);
        }

        using (response)
        {
            Uri? finalUri = response.RequestMessage?.RequestUri;
            if (finalUri is not null)
            {
                RequireHttps(finalUri, "response URL");
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new RakomiDiscoveryException(
                    $"{uri} answered with HTTP {(int)response.StatusCode}.",
                    response.StatusCode);
            }

            if (response.Content.Headers.ContentLength > MaxDocumentBytes)
            {
                throw new RakomiDiscoveryException($"The document at {uri} is larger than {MaxDocumentBytes} bytes.");
            }

            byte[] body = await ReadBoundedAsync(response.Content, uri, cancellationToken).ConfigureAwait(false);
            try
            {
                return JsonDocument.Parse(body);
            }
            catch (JsonException ex)
            {
                throw new RakomiDiscoveryException($"The document at {uri} is not valid JSON.", ex);
            }
        }
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpContent content, Uri uri, CancellationToken cancellationToken)
    {
        Stream stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            using MemoryStream buffer = new();
            byte[] chunk = new byte[16 * 1024];
            int read;
            while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > MaxDocumentBytes)
                {
                    throw new RakomiDiscoveryException($"The document at {uri} is larger than {MaxDocumentBytes} bytes.");
                }

                buffer.Write(chunk, 0, read);
            }

            return buffer.ToArray();
        }
    }

    internal static RakomiProviderMetadata ParseMetadata(JsonElement root, string expectedIssuer)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new RakomiDiscoveryException("The provider metadata is not a JSON object.");
        }

        string issuer = RequiredString(root, "issuer");
        if (!string.Equals(issuer, expectedIssuer, StringComparison.Ordinal))
        {
            throw new RakomiDiscoveryException(
                $"The provider metadata names the issuer '{issuer}', not the expected '{expectedIssuer}'.");
        }

        return new RakomiProviderMetadata
        {
            Issuer = issuer,
            AuthorizationEndpoint = RequiredHttpsUri(root, "authorization_endpoint"),
            TokenEndpoint = RequiredHttpsUri(root, "token_endpoint"),
            JwksUri = RequiredHttpsUri(root, "jwks_uri"),
            UserInfoEndpoint = OptionalHttpsUri(root, "userinfo_endpoint"),
            RevocationEndpoint = OptionalHttpsUri(root, "revocation_endpoint"),
            EndSessionEndpoint = OptionalHttpsUri(root, "end_session_endpoint"),
            DeviceAuthorizationEndpoint = OptionalHttpsUri(root, "device_authorization_endpoint"),
            ResponseTypesSupported = RequiredStringArray(root, "response_types_supported"),
            SubjectTypesSupported = RequiredStringArray(root, "subject_types_supported"),
            IdTokenSigningAlgValuesSupported = RequiredStringArray(root, "id_token_signing_alg_values_supported"),
            ScopesSupported = OptionalStringArray(root, "scopes_supported"),
            GrantTypesSupported = OptionalStringArray(root, "grant_types_supported"),
            CodeChallengeMethodsSupported = OptionalStringArray(root, "code_challenge_methods_supported"),
            TokenEndpointAuthMethodsSupported = OptionalStringArray(root, "token_endpoint_auth_methods_supported"),
            Document = root.Clone(),
        };
    }

    internal static RakomiJsonWebKeySet ParseKeySet(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("keys", out JsonElement keysElement)
            || keysElement.ValueKind != JsonValueKind.Array)
        {
            throw new RakomiDiscoveryException("The JSON Web Key Set has no 'keys' array.");
        }

        List<RakomiJsonWebKey> keys = new();
        foreach (JsonElement key in keysElement.EnumerateArray())
        {
            if (key.ValueKind != JsonValueKind.Object)
            {
                throw new RakomiDiscoveryException("A member of the JSON Web Key Set is not a JSON object.");
            }

            foreach (string member in PrivateKeyMembers)
            {
                if (key.TryGetProperty(member, out _))
                {
                    throw new RakomiDiscoveryException($"A key of the JSON Web Key Set carries the private member '{member}'.");
                }
            }

            keys.Add(new RakomiJsonWebKey
            {
                KeyType = RequiredString(key, "kty"),
                KeyId = OptionalString(key, "kid"),
                Use = OptionalString(key, "use"),
                Algorithm = OptionalString(key, "alg"),
                Modulus = OptionalString(key, "n"),
                Exponent = OptionalString(key, "e"),
                Curve = OptionalString(key, "crv"),
                X = OptionalString(key, "x"),
                Y = OptionalString(key, "y"),
                Json = key.Clone(),
            });
        }

        if (keys.Count == 0)
        {
            throw new RakomiDiscoveryException("The JSON Web Key Set has no keys.");
        }

        return new RakomiJsonWebKeySet { Keys = keys, Document = root.Clone() };
    }

    private static void RequireHttps(Uri uri, string what)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new RakomiDiscoveryException($"The {what} {uri} is not an absolute HTTPS URL.");
        }
    }

    private static string RequiredString(JsonElement obj, string name)
        => OptionalString(obj, name) ?? throw new RakomiDiscoveryException($"The required member '{name}' is missing or empty.");

    private static string? OptionalString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            throw new RakomiDiscoveryException($"The member '{name}' is not a string.");
        }

        string text = value.GetString()!;
        return text.Length == 0 ? null : text;
    }

    private static Uri RequiredHttpsUri(JsonElement obj, string name)
        => OptionalHttpsUri(obj, name) ?? throw new RakomiDiscoveryException($"The required member '{name}' is missing or empty.");

    private static Uri? OptionalHttpsUri(JsonElement obj, string name)
    {
        string? text = OptionalString(obj, name);
        if (text is null)
        {
            return null;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps)
        {
            throw new RakomiDiscoveryException($"The member '{name}' is not an absolute HTTPS URL.");
        }

        return uri;
    }

    private static IReadOnlyList<string> RequiredStringArray(JsonElement obj, string name)
    {
        IReadOnlyList<string> values = OptionalStringArray(obj, name);
        return values.Count > 0
            ? values
            : throw new RakomiDiscoveryException($"The required member '{name}' is missing or empty.");
    }

    private static IReadOnlyList<string> OptionalStringArray(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out JsonElement value) || value.ValueKind == JsonValueKind.Null)
        {
            return Array.Empty<string>();
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw new RakomiDiscoveryException($"The member '{name}' is not an array.");
        }

        List<string> values = new(value.GetArrayLength());
        foreach (JsonElement item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String)
            {
                throw new RakomiDiscoveryException($"The member '{name}' holds a value that is not a string.");
            }

            values.Add(item.GetString()!);
        }

        return values;
    }
}
