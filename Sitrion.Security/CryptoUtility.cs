using System.Security.Cryptography;
using System.Text;

namespace Sitrion.Security
{
    public static class CryptoUtility
    {
        /// <summary>
        /// Creates a cryptographic key using RNGCryptoServiceProvider
        /// </summary>
        /// <param name="keyLength">The length of the key. Typically 32 (256 bytes)</param>
        /// <returns>A cryptographically strong random byte array.</returns>
        /// <remarks>RNGCryptoServiceProvider has qualified through FIPS 140-2 certification. 
        /// Source: http://technet.microsoft.com/en-us/library/cc750357.aspx
        /// </remarks>
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

        private static readonly char[] Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

        public const int MaxSqlKey = 900;

        public static string GetUniqueKey(int maxSize)
        {
            byte[] data;
            using (var crypto = new RNGCryptoServiceProvider())
            {
                data = new byte[maxSize];
                crypto.GetBytes(data);
            }
            var result = new StringBuilder(maxSize);
            foreach (var b in data)
            {
                result.Append(Chars[b % (Chars.Length)]);
            }
            return result.ToString();
        }
    }
}
