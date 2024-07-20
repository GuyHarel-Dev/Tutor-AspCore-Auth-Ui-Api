using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace AspNetInfra
{
    public static class OpenIdConfig
    {
        public static RSA _rsa;
        public static RsaSecurityKey _rsaSecurityKey;
        public static string _publicKey;
        public static string _privateKey;
        public static RSAParameters _rsaParameters;

        static OpenIdConfig()
        {
            _rsa = new RSACryptoServiceProvider(2048);

            _publicKey = Convert.ToBase64String(_rsa.ExportRSAPublicKey());
            _privateKey = Convert.ToBase64String(_rsa.ExportRSAPrivateKey());

            _rsaSecurityKey = new RsaSecurityKey(_rsa);

            _rsaParameters = _rsa.ExportParameters(true);
        }

        public const string TokenIssuer = "https://localhost:7180";  // entité qui a émis le token
        public const string TokenAudience = "AspNetCoreApi_clientId";  // l'entité pour lesquelles le token est destiné.
    }
}
