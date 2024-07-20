using AspNetInfra;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewComponents;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AspNetCoreApi.Controllers
{
    [Route(".well-known")]
    [ApiController]
    public partial class OpenIdController : ControllerBase
    {
        private readonly ILogger<OpenIdController> logger;

        public OpenIdController(ILogger<OpenIdController> logger)
       {
            this.logger = logger;

        }

        [Route("openid-configuration")]
        [HttpGet]
        public IActionResult OnGetOpenIdConfig()
        {
            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(OnGetOpenIdConfig)} Request: {HttpHelper.RequestToString(Request)}");

            var issuer = OpenIdConfig.TokenIssuer;

            var openIdConfig = new OpenIdConfiguration
            {
                issuer = issuer, //L'URL de votre serveur OpenID Connect.
                authorization_endpoint = $"{issuer}/.well-known/authorize", // L'URL pour l'authentification (où les utilisateurs se connectent).
                token_endpoint = $"{issuer}/.well-known/token", // L'URL pour échanger le code d'autorisation contre un token d'accès et un token d'identité. 
                userinfo_endpoint = $"{issuer}/.well-known/userinfo", //  L'URL pour obtenir des informations sur l'utilisateur connecté.
                jwks_uri = $"{issuer}/.well-known/jwks.json", // L'URL pour obtenir les clés publiques utilisées pour vérifier les tokens JWT.

                response_types_supported = new[] { "code", "token", "id_token", "code id_token", "code token", "id_token token", "code id_token token" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256", "HS256" },
                scopes_supported = new[] { "openid", "profile", "email", "offline_access" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" }
            };

            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(OnGetOpenIdConfig)} reponse: {HttpHelper.JsonToString(openIdConfig)}");

            return new JsonResult(openIdConfig);
        }

    

        public IActionResult OnGet()
        {
            return new JsonResult(new { status = "je suis on get de /openid" });
        }

    


    }
}
