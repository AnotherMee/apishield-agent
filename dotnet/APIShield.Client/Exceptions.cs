using System.Net;

namespace APIShield.Client;

public class ApiShieldException : Exception
{
    public ApiShieldException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

public sealed class ApiShieldApiException : ApiShieldException
{
    public ApiShieldApiException(HttpStatusCode statusCode, string message)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode StatusCode { get; }
}

public sealed class ApiShieldTimeoutException : ApiShieldException
{
    public ApiShieldTimeoutException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class ApiShieldConnectionException : ApiShieldException
{
    public ApiShieldConnectionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class ApiShieldSerializationException : ApiShieldException
{
    public ApiShieldSerializationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
