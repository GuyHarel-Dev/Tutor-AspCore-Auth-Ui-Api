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

            builder.Services.AddLogging();
            builder.Services.AddSingleton<JwtTokenTest>(new JwtTokenTest());

            // Configure le délai pour les HTTPClient des middleware

            builder.Services.AddHttpClient("DefaultClient")
                .ConfigureHttpClient(client =>
                {
                    client.Timeout = TimeSpan.FromHours(2);
                });

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
                options.Authority = Config.OpenIdApi_URL; // L'URL de votre fournisseur d'OpenID Connect
                options.ClientId = "AspNetCoreApi_clientId"; //  Configuration["Authentication:OIDC:ClientId"];
                options.ClientSecret = "AspNetCoreApi_secret"; // Configuration["Authentication:OIDC:ClientSecret"];
                options.ResponseType = "code"; // Utilisation du flux de code d'autorisation
                options.SaveTokens = false; // true; // Enregistrer les jetons pour une utilisation ultérieure

                options.Configuration = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration
                {
                    AuthorizationEndpoint = "https://localhost:7180"
                };

                //options.ForwardChallenge = CookieAuthenticationDefaults.AuthenticationScheme;

                options.CallbackPath = new PathString("/signin-oidc");

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = AspNetInfra.OpenIdConfig.TokenIssuer,
                    ValidateAudience = true,
                    ValidAudience = AspNetInfra.OpenIdConfig.TokenAudience,
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
                    //,
                    //OnAuthorizationCodeReceived = context =>
                    //{
                    //    return Task.FromResult(new AuthorizationCodeReceivedContext(context)); // utilisé par HandleRemoteAuthenticateAsync() de OpenIdConnectHandler
                    //}
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

            }
            if (app.Environment.IsDevelopment())
            {
                IdentityModelEventSource.ShowPII = true;
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapRazorPages();

            app.Run();
        }
    }
}
