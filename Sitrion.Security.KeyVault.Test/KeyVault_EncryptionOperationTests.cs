using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Azure.KeyVault;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.WebKey;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Configuration;

namespace Sitrion.Security.KeyVault.Test
{
    [TestClass]
    public class KeyVault_EncryptionOperationTests
    {
        [TestMethod]
        public async Task KeyVault_EncryptionOperations()
        {
            string vault = ConfigurationManager.AppSettings["keyvault-uri"];
            var auth = TestUtil.Auth;
            var kv = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(auth.GetToken));

            string keyName = "unitTestKey";
            KeyBundle kb = null;

            try
            {
                kb = await kv.GetKeyAsync(vault, keyName);
            }
            catch (KeyVaultClientException kex)
            {
                Console.WriteLine(kex.Message);
                Console.WriteLine(kex.Status);
            }
            if (kb == null)
            {
                // JsonWebKeyType.RsaHsm for production! But not for test, these are $1/key. 
                kb = await kv.CreateKeyAsync(vault, keyName, JsonWebKeyType.Rsa);
            }

            var publicKey = kb.Key.N;

            byte[] aesKey = CreateCryptograhicKey(32);
            string plainAesString = Encoding.UTF8.GetString(aesKey);


            var rsa = kb.Key.ToRSA();
            var rsaWrappedBytes = rsa.Encrypt(aesKey, true); //2ms

            var kvWrappedBytes = await kv.WrapKeyAsync(kb.Key, aesKey, JsonWebKeyEncryptionAlgorithm.RSAOAEP); //141ms

            var unwrappedKey = await KeyVaultClientExtensions.UnwrapKeyAsync(kv, kb, rsaWrappedBytes, 
                JsonWebKeyEncryptionAlgorithm.RSAOAEP);
            
            string unwrappedKeyString = Encoding.UTF8.GetString(unwrappedKey.Result);

            Assert.AreEqual(plainAesString, unwrappedKeyString);
        }

        public static byte[] CreateCryptograhicKey(int keyLength)
        {
            using (var crypto = new RNGCryptoServiceProvider(new
                CspParameters
            { Flags = CspProviderFlags.UseArchivableKey }))
            {
                byte[] key = new byte[keyLength];
                crypto.GetBytes(key);
                return key;
            }
        }
        
    }
}
