using Sitrion.Security.KeyVault;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sitrion.Security.KeyVault.Test
{
    public class TestUtil
    {
        public static readonly IAdalTokenProvider Auth = 
            new SecretAuthentication(
                ConfigurationManager.AppSettings["keyvault-clientid1"],
                ConfigurationManager.AppSettings["keyvault-secret1"]);
    }
}
