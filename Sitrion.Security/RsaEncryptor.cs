using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sitrion.Security
{
    public class RsaEncryptor : IBinaryEncryptor, IDisposable
    {
        private X509Certificate2 Certificate { get; }

        public RsaEncryptor(X509Certificate2 cert)
        {
            if (cert == null)
                throw new ArgumentNullException();
            Certificate = cert;
        }

        public byte[] DecryptBytes(byte[] encryptedValue)
        {
            using (var RSA = Certificate.GetRSAPrivateKey())
            {
                return RSA.Decrypt(encryptedValue, RSAEncryptionPadding.Pkcs1);
            }
        }

        public byte[] EncryptBytes(byte[] data)
        {
            using (var RSA = Certificate.GetRSAPublicKey())
            {
                return RSA.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }

        public void Dispose()
        {
            ((IDisposable)Certificate).Dispose();
        }
    }
}
