using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Azure.KeyVault;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Configuration;

namespace Sitrion.Security.KeyVault.Test
{
    [TestClass]
    public class AuthTest
    {
        [TestMethod]
        public async Task KeyVault_SecretAuthentication()
        {
            var clientId = ConfigurationManager.AppSettings["keyvault-clientid1"];
            var clientSecret = ConfigurationManager.AppSettings["keyvault-secret1"]; 
            string vault = ConfigurationManager.AppSettings["keyvault-uri"];

            var auth = new SecretAuthentication(clientId, clientSecret);
            var kv = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(auth.GetToken));
                        
            try
            {

                var secrets = await kv.GetSecretsAsync(vault);
                foreach (var secret in secrets.Value)
                {
                    Console.WriteLine(secret.Id);
                }
            }
            catch (Microsoft.Azure.KeyVault.KeyVaultClientException kex)
            {
                Console.WriteLine(kex.Message);
            }
        }

        [TestMethod][ExpectedException(typeof(AdalServiceException))]
        public async Task KeyVault_SecretAuthentication_BadSecret()
        {
            var clientId = ConfigurationManager.AppSettings["keyvault-clientid1"];
            string vault = ConfigurationManager.AppSettings["keyvault-uri"];

            var auth = new SecretAuthentication(clientId, "imabadsecret");
            var kv = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(auth.GetToken));
            try
            {
                var secrets = await kv.GetSecretsAsync(vault);
            }
            catch (AdalServiceException)
            {
                Console.WriteLine("Caught expected AdalServiceException!!!");
                throw;
            }
            catch (Microsoft.Azure.KeyVault.KeyVaultClientException kex)
            {
                Console.WriteLine(kex.Message); // we'll get here if we authenticated but a permission for list wasn't granted.
            }
            Assert.Inconclusive("This test won't throw the AdalServiceException if KV was previously authenticated.");
        }

        [TestMethod]
        public async Task KeyVault_CertificateAuthentication()
        {
            var clientId = ConfigurationManager.AppSettings["keyvault-clientId"];
            string vault = ConfigurationManager.AppSettings["keyvault-uri"];
            var thumbprint =  ConfigurationManager.AppSettings["keyvault-thumbprint"];  
            try
            {
                     
                var auth = new CertificateAuthentication(clientId, thumbprint);
                var kv = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(auth.GetToken));
                            

                var secrets = await kv.GetSecretsAsync(vault);
                foreach (var secret in secrets.Value)
                {
                    Console.WriteLine(secret.Id);
                }
            }
            catch (Microsoft.Azure.KeyVault.KeyVaultClientException kex)
            {
                Console.WriteLine(kex.Message);
            }
            catch (ArgumentNullException)
            {
                Assert.Inconclusive("The authentication certificate isn't installed on this machine, so you can't run this test.");
            }
        }

        public static X509Certificate2 LoadCertificateByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint)
        {
            using (X509Store store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (certificates.Count > 0)
                {
                    return certificates[0];
                }

                foreach (var cert in store.Certificates.Cast<X509Certificate2>().Where(x => x.Thumbprint != null))
                {
                    if (cert.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase))
                        return new X509Certificate2(cert);
                }

                return null;
            }
        }
    }
}
