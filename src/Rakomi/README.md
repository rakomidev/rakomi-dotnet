# Rakomi

OpenID Connect discovery for [Rakomi](https://rakomi.com) issuers, for .NET 8 and later.

```sh
dotnet add package Rakomi
```

```csharp
using Rakomi;

RakomiDiscoveryResult result = await RakomiDiscovery.DiscoverAsync(new Uri("https://api.rakomi.com"));

Console.WriteLine(result.Metadata.TokenEndpoint);
foreach (RakomiJsonWebKey key in result.Keys.Keys)
{
    Console.WriteLine($"{key.KeyId} {key.KeyType} {key.Algorithm}");
}
```

`DiscoverAsync` fetches `{issuer}/.well-known/openid-configuration` and the JSON Web Key Set at its
`jwks_uri`, and throws `RakomiDiscoveryException` unless:

- the issuer and every URL in the document are absolute HTTPS URLs, and no response redirects;
- the document's `issuer` is equal, character for character, to the issuer you passed;
- the members OpenID Connect Discovery requires are present (`authorization_endpoint`, `token_endpoint`,
  `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported`);
- the key set has at least one key, each with a `kty` and no private key members;
- both documents are valid JSON of at most 1 MiB and arrive within the timeout (10 seconds by default).

An overload takes your own `HttpClient` and timeout:

```csharp
RakomiDiscoveryResult result = await RakomiDiscovery.DiscoverAsync(
    new Uri("https://api.rakomi.com"), httpClient, TimeSpan.FromSeconds(5), cancellationToken);
```

This package does not validate tokens; the keys it returns are the input for that.

License: MIT.
