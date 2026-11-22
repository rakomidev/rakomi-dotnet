# Rakomi for .NET

.NET packages for [Rakomi](https://rakomi.com).

| Package | What it does |
|---|---|
| [`Rakomi`](src/Rakomi/README.md) | OpenID Connect discovery: fetches and validates the provider metadata and JSON Web Key Set of a Rakomi issuer. |
| [`Rakomi.Sdk`](src/Rakomi.Sdk/README.md) | The Rakomi SDK. Early release: it currently brings in `Rakomi`. |

Both target .NET 8 and later.

```sh
dotnet add package Rakomi
```

```csharp
using Rakomi;

RakomiDiscoveryResult result = await RakomiDiscovery.DiscoverAsync(new Uri("https://api.rakomi.com"));
Console.WriteLine(result.Metadata.TokenEndpoint);
```

## Build

```sh
dotnet test
dotnet pack -c Release -o dist
```

The SDK version is pinned in `global.json`.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
