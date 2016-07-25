using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using System.Configuration;

namespace Sitrion.Security.Test
{
    [TestClass]
    public class RsaEncryptorTest
    {
        [TestMethod]
        public void EncDecTest()
        {
            var thumb = ConfigurationManager.AppSettings["Thumbprint"];

            if(string.IsNullOrEmpty(thumb))
                Assert.Inconclusive("A test cert was not configured. Go fish!");

            thumb = thumb.Replace(" ", string.Empty);
            var cert = CertificateHelper.LoadCertificateByThumbprint(thumb);
            try
            {
                Assert.IsNotNull(cert);
            }
            catch {
                Assert.Inconclusive("Couldn't load the test cert. Go fish!");
            }
            string hello = Guid.NewGuid().ToString();

            var enc = new RsaEncryptor(cert);

            var e = enc.EncryptBytes(Encoding.UTF8.GetBytes(hello));
            var s = Encoding.UTF8.GetString(enc.DecryptBytes(e));

            Assert.AreEqual(s, hello);


        }
    }
}
