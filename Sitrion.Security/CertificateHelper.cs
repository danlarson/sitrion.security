using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Sitrion.Security
{
    public static class CertificateHelper
    {
        public static X509Certificate2 LoadCertificateByThumbprint(string thumbprint)
        {
            return LoadCertificateByThumbprint(StoreName.My, StoreLocation.LocalMachine, thumbprint);
        }

        public static X509Certificate2 LoadCertificateByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint)
        {
            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);

                var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (certCollection.Count > 0)
                    return certCollection[0];

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