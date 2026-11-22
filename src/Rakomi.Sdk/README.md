# Rakomi.Sdk

The Rakomi SDK for .NET. This is an early release: today it brings in the
[`Rakomi`](https://www.nuget.org/packages/Rakomi) package, which provides OpenID Connect discovery
(`RakomiDiscovery.DiscoverAsync`). Further parts of the SDK will ship in later versions of this package.

```sh
dotnet add package Rakomi.Sdk
```

```csharp
using Rakomi;

RakomiDiscoveryResult result = await RakomiDiscovery.DiscoverAsync(new Uri("https://api.rakomi.com"));
Console.WriteLine(result.Metadata.Issuer);
```

License: MIT.
