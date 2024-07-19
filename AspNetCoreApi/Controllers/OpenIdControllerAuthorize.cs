using AspNetInfra;
using Microsoft.AspNetCore.Mvc;

namespace AspNetCoreApi.Controllers
{
    public partial class OpenIdController : ControllerBase
    {
        [Route("authorize")]
        public IActionResult Authorize()
        {
            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(Authorize)} Request: {HttpHelper.RequestToString(Request)}");

            var queryParameters = Request.Query;

            // Extract query parameters
            var clientId = queryParameters["client_id"].ToString();
            var redirectUri = queryParameters["redirect_uri"].ToString();
            var responseType = queryParameters["response_type"].ToString();
            var scope = queryParameters["scope"].ToString();
            var codeChallenge = queryParameters["code_challenge"].ToString();
            var codeChallengeMethod = queryParameters["code_challenge_method"].ToString();
            var responseMode = queryParameters["response_mode"].ToString();
            var nonce = queryParameters["nonce"].ToString();
            var state = queryParameters["state"].ToString();
            var xClientSKU = queryParameters["x-client-SKU"].ToString();
            var xClientVer = queryParameters["x-client-ver"].ToString();

            // Validate required parameters
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri) || string.IsNullOrEmpty(responseType) ||
                string.IsNullOrEmpty(scope) || string.IsNullOrEmpty(codeChallenge) || string.IsNullOrEmpty(codeChallengeMethod))
            {
                return BadRequest("Missing required query parameters.");
            }

            // TODO: Implement additional validation and processing logic
            // For example, validate client_id, redirect_uri, etc.

            // Generate authorization code
            var authorizationCode = "8266622accda4e81a4f0b66cb5331d32"; // GenerateAuthorizationCode();

            // Construct the response URL
            var responseUrl = $"{redirectUri}?code={authorizationCode}&state={state}";

            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(Authorize)} reponse: {HttpHelper.JsonToString(responseUrl)}");

            return new RedirectResult(responseUrl);

        }
    }
}
