using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Sitrion.Security
{
    /// <summary>
    /// A general purpose AES Encryption class. 
    /// </summary>
    public abstract class AesEncryptor : IBinaryEncryptor
    {        
        protected byte[] Key;

        protected virtual void Initialize()
        {}
               
        public const int KeyLength = 32;

        protected byte[] CreateCryptograhicKey()
        {
            return CryptoUtility.CreateCryptograhicKey(KeyLength);
        }
        
        public string DecryptString(byte[] input)
        {
            var decryptedBytes = Decrypt(input);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        public byte[] EncryptString(string toEncrypt)
        {
            if (string.IsNullOrEmpty(toEncrypt))
                return new byte[0];

            var toEncryptBytes = Encoding.UTF8.GetBytes(toEncrypt);
            return Encrypt(toEncryptBytes);
        }

        /// <summary>
        /// Encrypts a string along with the logical key the string relates to, when the data originates from a known primary key.
        /// </summary>
        /// <param name="logicalKey">The logical key the string relates to. 
        /// NOT used for cyphertext functions, only for data validation on decryption.</param>
        /// <param name="toEncrypt">The clear text to encrypt</param>
        /// <returns>Encrypted bytes</returns>
        /// <remarks>Use this when you're encrypting data that is unique to a database record, 
        /// such as a credential keyed to the user "nate@sitrion.com". Prevents Nate's corp creds from being copied to Dan.
        /// </remarks>
        public byte[] EncryptKeyedString(string logicalKey, string toEncrypt)
        {
            if (string.IsNullOrEmpty(toEncrypt))
                return new byte[0];

            var toEncryptBytes = Encoding.UTF8.GetBytes(logicalKey + toEncrypt);
            return Encrypt(toEncryptBytes);
        }

        /// <summary>
        /// Used to decrypt a keyed value when the data originates from a known foriegn key.
        /// </summary>
        /// <param name="logicalKey">The logical key the string relates to. 
        /// NOT used for cyphertext functions, only for data validation on decryption. 
        /// The key is NOT used as salt but rather to ensure this cyphertext belongs to the "owner" of the data 
        /// that it is assigned to. 
        /// </param>
        /// <param name="input">The encrypted data</param>
        /// <returns>The decrypted string if it was encrypted with the same logical key, otherwise null.</returns>
        /// <remarks>Prevents the same cyphertext to be copied to another database row and reused to impersonate another user.</remarks>
        public string DecryptKeyedString(string logicalKey, byte[] input)
        {
            string decrypted =DecryptString(input);

            // If the logical key doesn't match, return null. This code is enabling the calling code to 
            // ensure the data belongs to the foriegn key. 
            if (decrypted != null && decrypted.Substring(0, logicalKey.Length) == logicalKey)
                return decrypted.Substring(logicalKey.Length);
            return null;
        }

        public byte[] Encrypt(byte[] toEncryptBytes)
        {
            if (Key == null)
                Initialize();
            return Encrypt(Key, toEncryptBytes);            
        }

        public static byte[] Encrypt(byte[] encryptionKey, byte[] toEncryptBytes)
        {
            if (toEncryptBytes == null || toEncryptBytes.Length == 0)
                return new byte[0];

            if (encryptionKey == null || encryptionKey.Length == 0) throw new ArgumentException("encryptionKey");

            using (var aes = new AesCryptoServiceProvider
            {
                Key = encryptionKey,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {
                aes.GenerateIV();
                var iv = aes.IV;
                ICryptoTransform encrypter = null;
                try
                {
                    encrypter = aes.CreateEncryptor(aes.Key, iv);
                    MemoryStream cipherStream = null;
                    try
                    {
                        cipherStream = new MemoryStream();
                        CryptoStream tCryptoStream = null;
                        try
                        {
                            tCryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write);
                            using (var tBinaryWriter = new BinaryWriter(tCryptoStream))
                            {
                                //Prepend IV to data
                                cipherStream.Write(iv, 0, iv.Length);
                                tBinaryWriter.Write(toEncryptBytes);
                                tCryptoStream.FlushFinalBlock();
                            }
                        }
                        finally
                        {
                            tCryptoStream?.Dispose();
                        }
                        return cipherStream.ToArray();
                    }
                    finally
                    {
                        cipherStream?.Dispose();
                    }
                }
                finally
                {
                    encrypter?.Dispose();
                }
            }
        }

        public byte[] Decrypt(byte[] input)
        {
            if (input == null || input.Length == 0)
                return new byte[0];

            if (this.Key == null)
                Initialize();

            return Decrypt(this.Key, input);
        }

        public static byte[] Decrypt(byte[] encryptionKey, byte[] input)
        {
            if (input == null || input.Length == 0)
                return new byte[0];
                       

            var aes = new AesCryptoServiceProvider()
            {
                Key = encryptionKey,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            //get first 16 bytes of IV and use it to decrypt
            var iv = new byte[16];
            Array.Copy(input, 0, iv, 0, iv.Length);

            MemoryStream ms = null;
            try
            {
                ms = new MemoryStream();
                CryptoStream cs = null;
                try
                {
                    cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, iv), CryptoStreamMode.Write);
                    using (var binaryWriter = new BinaryWriter(cs))
                    {
                        //Decrypt Cipher Text from Message
                        binaryWriter.Write(
                            input,
                            iv.Length,
                            input.Length - iv.Length
                            );
                    }
                }
                finally
                {
                    if (ms != null)
                        ms.Dispose();
                }
                return ms.ToArray();
            }
            finally
            {
                if (ms != null)
                    ms.Dispose();
            }
        }

        byte[] IBinaryEncryptor.DecryptBytes(byte[] encryptedValue)
        {
            return this.Decrypt(encryptedValue);
        }

        byte[] IBinaryEncryptor.EncryptBytes(byte[] data)
        {
            return this.Encrypt(data);
        }
    }
}
