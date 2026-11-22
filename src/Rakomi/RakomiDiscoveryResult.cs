// SPDX-License-Identifier: MIT
namespace Rakomi;

/// <summary>The outcome of <see cref="RakomiDiscovery.DiscoverAsync(System.Uri, System.Threading.CancellationToken)"/>.</summary>
public sealed class RakomiDiscoveryResult
{
    internal RakomiDiscoveryResult(RakomiProviderMetadata metadata, RakomiJsonWebKeySet keys)
    {
        Metadata = metadata;
        Keys = keys;
    }

    /// <summary>The provider metadata of the issuer.</summary>
    public RakomiProviderMetadata Metadata { get; }

    /// <summary>The JSON Web Key Set published at <see cref="RakomiProviderMetadata.JwksUri"/>.</summary>
    public RakomiJsonWebKeySet Keys { get; }
}
