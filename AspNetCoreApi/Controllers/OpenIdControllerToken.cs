using AspNetInfra;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AspNetCoreApi.Controllers
{
    public partial class OpenIdController : ControllerBase
    {
        [Route("token")]
        [HttpPost]
        public IActionResult Token()
        {
            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(Token)} Request: {HttpHelper.RequestToString(Request)}");

            var request = Request.Form;

            // TODO: Valider la requète: client client_id, le client_secret, le grant_type, le code(authorisation code flow)

            // Validate the client_id and client_secret
            var clientId = request["client_id"];
            var clientSecret = request["client_secret"];
            //if (!ValidateClient(clientId, clientSecret))
            //{
            //    return BadRequest(new { error = "invalid_client" });
            //}

            // Validate the grant_type
            var grantType = request["grant_type"];
            //if (grantType != "authorization_code")
            //{
            //    return BadRequest(new { error = "unsupported_grant_type" });
            //}

            // Validate the authorization code
            var code = request["code"];

            // Generate the access token
            var token = GenerateToken();
            var token_id = GenerateIdToken(clientId, StaticNonce);


            var reponse = new
            {
                access_token = token,
                token_type = "Bearer",
                expires_in = 360000, // 1 hour expiration time
                id_token = token_id
            };

            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(Token)} reponse: {HttpHelper.JsonToString(reponse)}");

            // Return the token response
            return new JsonResult(reponse);
        }

        // Pour signer un token JWT avec la clé privée:

        private string GenerateToken()
        {
            // Générer un token JWT
            var tokenHandler = new JsonWebTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("sub", "1234567890"), new Claim("name", "John Doe") }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(VouteClefRSA.RSAParameters), SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            //var tokenString = tokenHandler.w

            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(GenerateToken)} token: {HttpHelper.JsonToString(token)}");

            return token;
        }

        // Pour valider un token JWT avec la clé publique
        //public void ValidateToken(string tokenString)
        //{
        //    var tokenHandler = new JsonWebTokenHandler();
        //    var validationParameters = new TokenValidationParameters
        //    {
        //        ValidateIssuer = false,
        //        ValidateAudience = false,
        //        ValidateLifetime = true,
        //        ValidateIssuerSigningKey = true,
        //        IssuerSigningKey = new RsaSecurityKey(_rsaParameters)
        //    };

        //    SecurityToken validatedToken;
        //    var principal = tokenHandler.ValidateToken(tokenString, validationParameters, out validatedToken);

        //}

        private string GenerateIdToken(string clientId, string nonce)
        {
            var tokenHandler = new JsonWebTokenHandler();

            var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, "1234567890"),
                    new Claim(JwtRegisteredClaimNames.Name, "John Doe"),
                    new Claim(JwtRegisteredClaimNames.Email, "johndoe@example.com"),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Aud, clientId),
                    new Claim(JwtRegisteredClaimNames.Iss, Config.Appli_URL),
                    new Claim(JwtRegisteredClaimNames.Nonce, nonce)
                };

            var rsaSecurityKey = new RsaSecurityKey(VouteClefRSA.RSAParameters)
            {
                KeyId = "112233"
            };


            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            logger.LogInformation($"{nameof(OpenIdController)}/{nameof(GenerateIdToken)} token: {HttpHelper.JsonToString(token)}");

            return token;
        }
    }
    //private string GenerateToken(string clientId)
    //{
    //    var claims = new[]
    //    {
    //    new Claim(JwtRegisteredClaimNames.Sub, clientId),
    //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
    //    new Claim(JwtRegisteredClaimNames.Website, "test_2"),
    //};

    //    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey128Bits));
    //    key.KeyId = "222333444";
    //    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);


    //    var token = new JwtSecurityToken(
    //        issuer: "your_issuer",
    //        audience: "your_audience",
    //        claims: claims,
    //        expires: DateTime.Now.AddDays(1),
    //        signingCredentials: creds);

    //    var res = new JwtSecurityTokenHandler().WriteToken(token);
    //    return res;
    //}

    //private string GenerateIdToken(string clientId)
    //{
    //    var claims = new[]
    //           {
    //    new Claim(JwtRegisteredClaimNames.Sub, clientId),
    //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
    //    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
    //    new Claim(JwtRegisteredClaimNames.Website, "test_1"),
    //    };

    //    // Génération de la paire de clés RSA
    //    RSA _rsa = RSA.Create(2048);
    //    var key = new RsaSecurityKey(_rsa)
    //    {
    //        KeyId = _kid
    //    };

    //    var creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

    //    var token = new JwtSecurityToken(
    //        issuer: Config.Appli_URL,
    //        audience: "AspNetCoreApi_clientId",
    //        claims: claims,
    //        expires: DateTime.Now.AddHours(1),
    //        signingCredentials: creds);

    //    var res = new JwtSecurityTokenHandler().WriteToken(token);

    //    return res;
    //}

}
