//using AspNetInfra;
//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.Extensions.Logging;
//using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Security.Cryptography;
//using System.Text;

//namespace AspNetCoreApi.Controllers
//{
//    [Route("connect")]
//    [ApiController]
//    public class OpenIdConnectController : ControllerBase
//    {
//        private readonly ILogger<OpenIdConnectController> logger;



//        //private readonly RSA _rsa;
//        private readonly string _kid = "12345"; // Identifiant de la clé (kid)

//        public OpenIdConnectController(ILogger<OpenIdConnectController> logger)
//        {
//            this.logger = logger;
//        }

    

//        [Route("userinfo")]
//        public IActionResult UserInfo()
//        {
//            logger.LogInformation($"{nameof(OpenIdConnectController)}/{nameof(UserInfo)}: {HttpHelper.RequestToString(Request)}");
//            return Ok();
//        }


//        private string GenerateAuthorizationCode()
//        {
//            // TODO: Implement your authorization code generation logic
//            return Guid.NewGuid().ToString("N");
//        }


       

//        private string GenerateIdToken_ClefSymm(string clientId)
//        {
//            var claims = new[]
//            {
//                new Claim(JwtRegisteredClaimNames.Sub, clientId),
//                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
//                // Add more claims as needed
//                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
//                new Claim(JwtRegisteredClaimNames.Website, "test_1"),
//            };

//            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey128Bits));
//            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//            var token = new JwtSecurityToken(
//                issuer: Config.Appli_URL,
//                audience: "AspNetCoreApi_clientId",
//                claims: claims,
//                expires: DateTime.Now.AddHours(1),
//                signingCredentials: creds);

//            var res = new JwtSecurityTokenHandler().WriteToken(token);

//            return res;
//        }
//    }
//}
