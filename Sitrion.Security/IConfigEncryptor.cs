using System.Security.Cryptography.X509Certificates;

namespace Sitrion.Security
{
    public interface IConfigEncryptor
    {
        RsaEncryptor RsaEncryptor { get; set; }
        X509Certificate2 EncryptionCert { get; set; }
        string Encrypt(string label, string value);
        string Decrypt(string input);
    }
}