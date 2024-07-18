//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Http;
//using Microsoft.AspNetCore.Mvc;
//using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Text;
//using System.Text.Json;

//namespace AspNetCoreApi.Controllers
//{
//    [Route("api/[controller]/obtenir-token")]
//    [ApiController]
//    public class JwtController : ControllerBase
//    {
//        [HttpPost]
//        public IActionResult ObtenirToken([FromForm] Credential credential)
//        {
//            return CreateToken(credential);
//        }

//        private JsonResult CreateToken(Credential credential)
//        {
//            var claims = new[]
//            {
//                new Claim(JwtRegisteredClaimNames.Sub, credential.username),
//                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
//            };

//            // Secret Key
//            var secretKey128Bits = "6b9d5e8f3a4b2c1d0e6f7a8b9c0d1e2f3b4c5d6e7f8a9b0c1d2e3f4g5h6i7j8k";
//            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey128Bits));

//            // Credentials
//            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

//            // Token
//            var token = new JwtSecurityToken(
//                issuer: "AspNetCoreApi.csproj",
//                audience: "AspNetCoreRazor.csproj",
//                claims: claims,
//                expires: DateTime.Now.AddMinutes(30),
//                signingCredentials: creds);

//            var test = JsonSerializer.Serialize(token);

//            return new JsonResult(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
//        }

       
//    }
//}
