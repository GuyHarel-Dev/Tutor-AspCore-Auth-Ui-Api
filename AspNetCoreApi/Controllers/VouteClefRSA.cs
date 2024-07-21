using System.Security.Cryptography;

namespace AspNetCoreApi.Controllers
{
    public static class VouteClefRSA
    {
        private static RSACryptoServiceProvider _rsaProvider;
        private static RSAParameters _rsaParameters;

        public static RSACryptoServiceProvider RSA { get { return _rsaProvider; } }
        public static RSAParameters RSAParameters { get { return _rsaParameters; } }

        static VouteClefRSA()
        {
            _rsaProvider = new RSACryptoServiceProvider(2048); // génération de la clef privé et publique
            _rsaParameters = _rsaProvider.ExportParameters(true);
        }
    }
}
