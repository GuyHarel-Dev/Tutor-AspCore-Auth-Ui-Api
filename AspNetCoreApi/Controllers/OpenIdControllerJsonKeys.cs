using AspNetInfra;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AspNetCoreApi.Controllers
{
    public partial class OpenIdController : ControllerBase
    {

        [HttpGet("jwks.json")]
        public IActionResult GetJwks()
        {
            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(GetJwks)} Request: {HttpHelper.RequestToString(Request)}");

            var jwks = new Jwks
            {
                Keys = new List<JwksKey>
            {
                new JwksKey
                {
                    Kty = "RSA",
                    Use = "sig",
                    Kid = "112233", // _rsaKey.KeyId, //Guid.NewGuid().ToString(), // "your-key-id",
                    Alg = "RS256",
                    N = Base64UrlEncode(_rsaParameters.Modulus), // "your-modulus-base64-url-encoded",
                    E = Base64UrlEncode(_rsaParameters.Exponent) //"your-exponent-base64-url-encoded"
                }
                }
            };

            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(GetJwks)} parameters: {HttpHelper.JsonToString(_rsaParameters)}");
            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(GetJwks)} reponse: {HttpHelper.JsonToString(jwks)}");

            return new JsonResult(jwks);
        }

        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }
    }
}
