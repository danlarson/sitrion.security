using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sitrion.Security.KeyVault.Test
{
    [TestClass]
    public class KeyVaultEncryptorTests
    {
        [TestMethod]
        public void KeyVaultEncryptor_Encrypt()
        {
            string vault = ConfigurationManager.AppSettings["keyvault-uri"];

            KeyVaultEncryptor enc = new KeyVaultEncryptor(vault, TestUtil.Auth) { Test = true};

            string keyname = "randomtenantid1";
            
            var key = enc.CreateKey(keyname);

            key = enc.GetKey(key.KeyIdentifier.Identifier);

            var aesKey = CryptoUtility.CreateCryptograhicKey(32);

            var encryptedKey = enc.WrapKey(key.Key, aesKey);
            var clearAesKey = enc.UnwrapKey(key.Key, encryptedKey);

            Assert.AreEqual( Encoding.UTF8.GetString(aesKey), Encoding.UTF8.GetString(clearAesKey));            
        }
    }
}
