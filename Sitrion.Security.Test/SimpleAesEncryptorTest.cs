using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace Sitrion.Security.Test
{
    [TestClass]
    public class SimpleAesEncryptorTest
    {
        [TestMethod]
        public void BasicEncDecrypt()
        {
            string hello = Guid.NewGuid().ToString();

            SimpleAesEncryptor enc = new SimpleAesEncryptor(null);
            var encrypted = enc.Encrypt(Encoding.UTF8.GetBytes(hello));

            Assert.IsFalse(Encoding.UTF8.GetString(encrypted) == hello);

            var dec = enc.DecryptString(encrypted);
            Assert.AreEqual(hello, dec);

        }

        [TestMethod]
        public void EncryptionsAreUniqueForSameData()
        {
            string hello = Guid.NewGuid().ToString();

            SimpleAesEncryptor enc = new SimpleAesEncryptor(null);

            var estring = Encoding.UTF8.GetString(enc.Encrypt(Encoding.UTF8.GetBytes(hello)));
            var estring2 = Encoding.UTF8.GetString(enc.Encrypt(Encoding.UTF8.GetBytes(hello)));
            var estring3 = Encoding.UTF8.GetString(enc.Encrypt(Encoding.UTF8.GetBytes(hello)));

            Assert.IsFalse(estring == null);
            Assert.IsFalse(estring == hello);
            Assert.IsFalse(estring == estring2);
            Assert.IsFalse(estring == estring3);
            Assert.IsFalse(estring2 == estring3);
        }

        [TestMethod]
        public void KeyedCyphertextCantBeCopiedToOtherKeys()
        {
            string hello = "hello";
            string key = "dan@example.com";
            string key2 = "bob@example.com";

            SimpleAesEncryptor enc = new SimpleAesEncryptor(null);

            var estring = enc.EncryptKeyedString(key, hello);
            var estring2 = enc.EncryptKeyedString(key2, hello);

            var decstring = enc.DecryptKeyedString(key, estring);
            var decstring2 = enc.DecryptKeyedString(key2, estring);


            Assert.IsNotNull(decstring);
            Assert.IsNull(decstring2);

            Assert.AreEqual(decstring, hello);
        }
    }
}
