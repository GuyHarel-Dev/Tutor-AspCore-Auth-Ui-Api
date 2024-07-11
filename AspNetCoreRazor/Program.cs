using AspNetCoreRazor.Security.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace AspNetCoreRazor
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddRazorPages();

            // Pour les test de Jwt
            builder.Services.AddHttpClient();
            builder.Services.AddLogging();
            builder.Services.AddSingleton<JwtTokenTest>(new JwtTokenTest());

            // Ajouter OpenID (qui contient Oauth 2.0)
            builder.Services.AddAuthentication(o =>
                {
                    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                }
            )
            .AddCookie()
            .AddOpenIdConnect(options =>
            {
                options.Authority = "https://localhost:7180"; // L'URL de votre fournisseur d'OpenID Connect
                options.ClientId = "AspNetCoreApi_clientId"; //  Configuration["Authentication:OIDC:ClientId"];
                options.ClientSecret = "AspNetCoreApi_secret"; // Configuration["Authentication:OIDC:ClientSecret"];
                options.ResponseType = "code"; // Utilisation du flux de code d'autorisation
                options.SaveTokens = true; // Enregistrer les jetons pour une utilisation ult�rieure

                //options.Configuration = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration
                //{
                //    AuthorizationEndpoint = "https://localhost:7180"
                //};

                //options.ForwardChallenge = CookieAuthenticationDefaults.AuthenticationScheme;

                options.CallbackPath = new PathString("/signin-oidc");

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = "https://localhost:7180",
                    ValidateAudience = true,
                    ValidAudience = "AspNetCoreApi_clientId",
                    ValidateLifetime = true
                };

                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        // Custom logic before redirecting to the identity provider
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        // Custom logic after token is validated
                        return Task.CompletedTask;
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = 500;
                        context.Response.ContentType = "application/json";
                        var result = JsonSerializer.Serialize(new { error = context.Exception.Message });
                        return context.Response.WriteAsync(result);
                    }
                };
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();

                // Show PII in development environment
                IdentityModelEventSource.ShowPII = true;
            }

            app.UseAuthentication();


            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthorization();

            app.MapRazorPages();

            app.Run();
        }
    }
}
