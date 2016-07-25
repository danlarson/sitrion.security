namespace Sitrion.Security
{
    /// <summary>
    /// A simle AES encryptor for use when you know the private key or if you just want to test the library.
    /// </summary>
    public class SimpleAesEncryptor : AesEncryptor
    {
        /// <summary>
        /// Creates an AES encryptor with a known key. If you need to generate the key pass in NULL. 
        /// </summary>
        /// <param name="key">The binary key. You should NEVER EVER generate this manually.</param>
        public SimpleAesEncryptor(byte[] key)
        {
            Key = key ?? CreateCryptograhicKey();
        }
    }
}
