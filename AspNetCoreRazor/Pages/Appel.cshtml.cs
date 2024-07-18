using AspNetCoreRazor.Security.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Net.Http.Headers;
using System.Net.Http;
using System.Text.Json;

namespace AspNetCoreRazor.Pages
{
    public class AppelModel : PageModel
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly JwtTokenTest jwtToken;

        public AppelModel( IHttpClientFactory httpClientFactory, JwtTokenTest jwtToken)
        {
            this.httpClientFactory = httpClientFactory;
            this.jwtToken = jwtToken;
           
        }

        public void OnGet()
        {
        }

        public IActionResult OnPost(string token)
        {
            // Tenter d'utiliser le api weather qui est progété par un JwtToken
            var httpClient = httpClientFactory.CreateClient();

            var requete = CreerRequeteMessage(jwtToken.JsonToken.token);
            var reponse = httpClient.Send(requete);

            return new JsonResult(new { statut = reponse.StatusCode, content = reponse.Content.ReadAsStringAsync().Result });
        }

        private HttpRequestMessage CreerRequeteMessage(string token)
        {
            HttpRequestMessage request = new HttpRequestMessage(
                HttpMethod.Get,
                $"{Config.OpenIdApi_URL}/WeatherForecast")
            {
                Headers =
                {
                    { HeaderNames.Authorization, $"Bearer {token}" }
                }
            };

            return request;
        }
    }
}
