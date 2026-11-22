// SPDX-License-Identifier: MIT
using System;
using System.Net;

namespace Rakomi;

/// <summary>
/// Thrown when OpenID Connect discovery fails: the issuer or a published URL is not HTTPS, a request fails or
/// times out, or a document is not valid JSON or lacks a required member.
/// </summary>
public sealed class RakomiDiscoveryException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public RakomiDiscoveryException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a message and the exception that caused it.</summary>
    public RakomiDiscoveryException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception for an HTTP response with a non-success status code.</summary>
    public RakomiDiscoveryException(string message, HttpStatusCode statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    /// <summary>Creates the exception without a message.</summary>
    public RakomiDiscoveryException()
    {
    }

    /// <summary>The HTTP status code when the failure was a non-success response; otherwise <see langword="null"/>.</summary>
    public HttpStatusCode? StatusCode { get; }
}
