//using AspNetInfra;
//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.AspNetCore.Mvc.ViewComponents;
//using Microsoft.IdentityModel.Tokens;
//using System.Security.Cryptography;
//using System.Text;
//using System.Text.Json;

//namespace AspNetCoreApi.Controllers
//{
//    [Route(".well-known")]
//    [ApiController]
//    public partial class OpenIdController : ControllerBase
//    {
//        private readonly ILogger<OpenIdController> logger;
//        //private static RSA _rsa;
//        private readonly RSACryptoServiceProvider _rsaProvider;
//        private readonly RSAParameters _rsaParameters;
//        private const String secretKey128Bits = "6b9d5e8f3a4b2c1d0e6f7a8b9c0d1e2f3b4c5d6e7f8a9b0c1d2e3f4g5h6i7j8k";

//        //private static RsaSecurityKey _rsaKey;

//        public OpenIdController(ILogger<OpenIdController> logger)
//        {
//            this.logger = logger;

//            // Initialisation des clés RSA  v1
//            _rsaProvider = new RSACryptoServiceProvider(2048); // génération de la clef privé et publique
//            _rsaParameters = _rsaProvider.ExportParameters(true);

//            // Initialisation des clés RSA  v2

//            //logger.LogInformation($"{nameof(OpenIdController)}/ctor _rsaProvider: {JsonSerializer.Serialize(_rsaProvider)}");
//            //logger.LogInformation($"{nameof(OpenIdController)}/ctor _rsaParameters: {JsonSerializer.Serialize(_rsaParameters)}");
//        }

//        [Route("openid-configuration")]
//        [HttpGet]
//        public IActionResult OnGetOpenIdConfig()
//        {
//            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(OnGetOpenIdConfig)} Request: {HttpHelper.RequestToString(Request)}");

//            var openIdConfig = new OpenIdConfiguration
//            {
//                issuer = Config.Appli_URL, //L'URL de votre serveur OpenID Connect.
//                authorization_endpoint = $"{Config.Appli_URL}/.well-known/authorize", // L'URL pour l'authentification (où les utilisateurs se connectent).
//                token_endpoint = $"{Config.Appli_URL}/.well-known/token", // L'URL pour échanger le code d'autorisation contre un token d'accès et un token d'identité. 
//                userinfo_endpoint = $"{Config.Appli_URL}/.well-known/userinfo", //  L'URL pour obtenir des informations sur l'utilisateur connecté.
//                jwks_uri = $"{Config.Appli_URL}/.well-known/jwks.json", // L'URL pour obtenir les clés publiques utilisées pour vérifier les tokens JWT.

//                response_types_supported = new[] { "code", "token", "id_token", "code id_token", "code token", "id_token token", "code id_token token" },
//                subject_types_supported = new[] { "public" },
//                id_token_signing_alg_values_supported = new[] { "RS256", "HS256" },
//                scopes_supported = new[] { "openid", "profile", "email", "offline_access" },
//                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" }
//            };

//            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(OnGetOpenIdConfig)} reponse: {HttpHelper.JsonToString(openIdConfig)}");

//            return new JsonResult(openIdConfig);
//        }

    

//        public IActionResult OnGet()
//        {
//            return new JsonResult(new { status = "je suis on get de /openid" });
//        }

    


//    }
//}
