using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Microsoft.Azure.KeyVault.KeyVaultClient;

namespace Sitrion.Security.KeyVault
{
    public class CertificateAuthentication : IAdalTokenProvider
    {
        private readonly ClientAssertionCertificate AssertionCert;

        public CertificateAuthentication(string clientId, string thumbprint)
        {
            var authCert = CertificateHelper.LoadCertificateByThumbprint(thumbprint);
            this.AssertionCert = new ClientAssertionCertificate(clientId, authCert);
        }

        public async Task<string> GetToken(string authority, string resource, string scope)
        {
            var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
            var result = await context.AcquireTokenAsync(resource, this.AssertionCert);
            return result.AccessToken;
        }
    }

    public class SecretAuthentication : IAdalTokenProvider
    {
        private readonly string clientId;
        private readonly string secret;

        public SecretAuthentication(string clientId, string clientSecret)
        {
            this.clientId = clientId;
            this.secret = clientSecret;
        }
        public async Task<string> GetToken(string authority, string resource, string scope)
        {
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(clientId, secret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }       
        
    }
}
