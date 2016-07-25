using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sitrion.Security.Test
{
    [TestClass]
    public class CryptoUtilityTest
    {
        [TestMethod]
        public void TestKeyGen()
        {
            var key = CryptoUtility.CreateCryptograhicKey(32);
            string skey = Convert.ToBase64String(key);
            Assert.IsNotNull(skey);
        }
    }
}
