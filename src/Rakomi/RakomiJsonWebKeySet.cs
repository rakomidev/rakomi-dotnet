// SPDX-License-Identifier: MIT
using System.Collections.Generic;
using System.Text.Json;

namespace Rakomi;

/// <summary>The JSON Web Key Set published at an issuer's <c>jwks_uri</c> (RFC 7517, section 5).</summary>
public sealed class RakomiJsonWebKeySet
{
    internal RakomiJsonWebKeySet()
    {
    }

    /// <summary>The keys of the set. Never empty.</summary>
    public required IReadOnlyList<RakomiJsonWebKey> Keys { get; init; }

    /// <summary>The whole document as received.</summary>
    public required JsonElement Document { get; init; }
}

/// <summary>One public key of a <see cref="RakomiJsonWebKeySet"/> (RFC 7517, section 4).</summary>
public sealed class RakomiJsonWebKey
{
    internal RakomiJsonWebKey()
    {
    }

    /// <summary>The <c>kty</c> member, for example <c>RSA</c> or <c>EC</c>.</summary>
    public required string KeyType { get; init; }

    /// <summary>The <c>kid</c> member, if present.</summary>
    public string? KeyId { get; init; }

    /// <summary>The <c>use</c> member, if present.</summary>
    public string? Use { get; init; }

    /// <summary>The <c>alg</c> member, if present.</summary>
    public string? Algorithm { get; init; }

    /// <summary>The RSA modulus <c>n</c> (base64url), if present.</summary>
    public string? Modulus { get; init; }

    /// <summary>The RSA exponent <c>e</c> (base64url), if present.</summary>
    public string? Exponent { get; init; }

    /// <summary>The elliptic curve <c>crv</c>, if present.</summary>
    public string? Curve { get; init; }

    /// <summary>The curve point coordinate <c>x</c> (base64url), if present.</summary>
    public string? X { get; init; }

    /// <summary>The curve point coordinate <c>y</c> (base64url), if present.</summary>
    public string? Y { get; init; }

    /// <summary>The key as received, for members this type does not model.</summary>
    public required JsonElement Json { get; init; }
}
