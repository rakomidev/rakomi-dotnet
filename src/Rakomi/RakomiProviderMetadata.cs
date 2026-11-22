// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Rakomi;

/// <summary>
/// The OpenID Provider metadata of an issuer, read from its <c>/.well-known/openid-configuration</c> document
/// (OpenID Connect Discovery 1.0, section 3). Every URL in it has been checked to be an absolute HTTPS URL.
/// </summary>
public sealed class RakomiProviderMetadata
{
    internal RakomiProviderMetadata()
    {
    }

    /// <summary>The <c>issuer</c> member. It is equal, character for character, to the issuer discovery was called with.</summary>
    public required string Issuer { get; init; }

    /// <summary>The <c>authorization_endpoint</c> member.</summary>
    public required Uri AuthorizationEndpoint { get; init; }

    /// <summary>The <c>token_endpoint</c> member.</summary>
    public required Uri TokenEndpoint { get; init; }

    /// <summary>The <c>jwks_uri</c> member.</summary>
    public required Uri JwksUri { get; init; }

    /// <summary>The <c>userinfo_endpoint</c> member, if published.</summary>
    public Uri? UserInfoEndpoint { get; init; }

    /// <summary>The <c>revocation_endpoint</c> member, if published.</summary>
    public Uri? RevocationEndpoint { get; init; }

    /// <summary>The <c>end_session_endpoint</c> member, if published.</summary>
    public Uri? EndSessionEndpoint { get; init; }

    /// <summary>The <c>device_authorization_endpoint</c> member, if published.</summary>
    public Uri? DeviceAuthorizationEndpoint { get; init; }

    /// <summary>The <c>response_types_supported</c> member.</summary>
    public required IReadOnlyList<string> ResponseTypesSupported { get; init; }

    /// <summary>The <c>subject_types_supported</c> member.</summary>
    public required IReadOnlyList<string> SubjectTypesSupported { get; init; }

    /// <summary>The <c>id_token_signing_alg_values_supported</c> member.</summary>
    public required IReadOnlyList<string> IdTokenSigningAlgValuesSupported { get; init; }

    /// <summary>The <c>scopes_supported</c> member; empty if not published.</summary>
    public IReadOnlyList<string> ScopesSupported { get; init; } = Array.Empty<string>();

    /// <summary>The <c>grant_types_supported</c> member; empty if not published.</summary>
    public IReadOnlyList<string> GrantTypesSupported { get; init; } = Array.Empty<string>();

    /// <summary>The <c>code_challenge_methods_supported</c> member; empty if not published.</summary>
    public IReadOnlyList<string> CodeChallengeMethodsSupported { get; init; } = Array.Empty<string>();

    /// <summary>The <c>token_endpoint_auth_methods_supported</c> member; empty if not published.</summary>
    public IReadOnlyList<string> TokenEndpointAuthMethodsSupported { get; init; } = Array.Empty<string>();

    /// <summary>The whole document as received, for members this type does not model.</summary>
    public required JsonElement Document { get; init; }
}
