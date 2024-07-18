using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Net.Http.Headers;
using System.Runtime.CompilerServices;
using AspNetCoreRazor.Security.Authentication;

namespace AspNetCoreRazor.Pages
{
    public class LoginModel : PageModel
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly JwtTokenTest jwtToken;

        public LoginModel(IHttpClientFactory httpClientFactory, JwtTokenTest jwtToken)
        {
            this.httpClientFactory = httpClientFactory;
            this.jwtToken = jwtToken;
        }

        public void OnGet()
        {

        }

        public IActionResult OnPost(string username, string password)
        {
            //// Obtenir le token JWT du serveur AspNetCoreApi

            //var httpClient = httpClientFactory.CreateClient();
            //var reponse = httpClient.Send(CreerRequeteMessage(username, password));
            //var token = reponse.Content.ReadFromJsonAsync<JwtTokenTest.JwtToken>().Result;
            //jwtToken.JsonToken = token;

            return new JsonResult(new { statut = "vide" });
        }

        //private HttpRequestMessage CreerRequeteMessage(string username, string password)
        //{
        //    var data = new FormUrlEncodedContent(new Dictionary<string, string>
        //    {
        //        { "username", username },
        //        { "password", password }
        //    });

        //    HttpRequestMessage request = new HttpRequestMessage(
        //        HttpMethod.Post,
        //        $"{Config.OpenIdApi_URL}/api/jwt/obtenir-token")
        //    {
        //        Content = data
        //    };

        //    return request;
        //}
    }
}
