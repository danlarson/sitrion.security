using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Sitrion.Security.KeyVault
{
    public enum KeyVaultAuthentication {
        none = 0, certificate = 1, secret = 2
    }

    public class KeyVaultKeyEncryptor : IBinaryEncryptor
    {
        private readonly string keyIdentifier;
        private readonly KeyVaultClient kv;

        public KeyVaultKeyEncryptor(IAdalTokenProvider auth, string keyId)
        {
            this.kv = new KeyVaultClient(auth.GetToken);
            this.keyIdentifier = keyId;
        }

        public JsonWebKey JsonKey { get; set; }

        public byte[] DecryptBytes(byte[] encryptedValue)
        {
            var task = kv.UnwrapKeyAsync(this.keyIdentifier, JsonWebKeyEncryptionAlgorithm.RSAOAEP, encryptedValue);
            task.Wait();
            return task.Result.Result;
        }

        public byte[] EncryptBytes(byte[] data)
        {
            if (JsonKey != null)
            {
                var rsa = JsonKey.ToRSA();
                return rsa.Encrypt(data, true);
            }
            var task = kv.WrapKeyAsync(this.keyIdentifier, JsonWebKeyEncryptionAlgorithm.RSAOAEP, data);
            task.Wait();
            return task.Result.Result;
        }
    }

    public class KeyVaultEncryptor 
    {
        private readonly KeyVaultClient kv;

        public bool Test { get; set; }

        public string VaultUri { get; private set; }

        //<add key="keyvault-clientId" value="f8a88944-6c69-4e64-ae09-87715bc14ff2"/>
        //<add key="keyvault-thumbprint" value="046fca1f1f4a23a1b5141f6890b513af1f0acd7d"/>
        //<add key="keyvault-uri" value="https://sitriondev-kv.vault.azure.net"/>

        public static KeyVaultEncryptor Create(string vaultUri, string clientId, string thumbprintOrSecret, KeyVaultAuthentication authType)
        {
            IAdalTokenProvider auth;
            if (authType == KeyVaultAuthentication.certificate)
                auth = new CertificateAuthentication(clientId, thumbprintOrSecret);
            else
                auth = new SecretAuthentication(clientId, thumbprintOrSecret);
            return new KeyVaultEncryptor(vaultUri, auth);
        }

        public KeyVaultEncryptor(string vaultUri, IAdalTokenProvider auth)
        {
            this.VaultUri = vaultUri;
            this.kv = new KeyVaultClient(auth.GetToken);
        }

        public byte[] WrapKey(JsonWebKey jkey, byte[] key)
        {
            var rsa = jkey.ToRSA();
            return rsa.Encrypt(key, true);
        }

        public async Task<byte[]> UnwrapKeyAsync(JsonWebKey jkey, byte[] key)
        {
            var unwrappedKey = await this.kv.UnwrapKeyAsync(jkey, key, JsonWebKeyEncryptionAlgorithm.RSAOAEP);
            return unwrappedKey.Result;
        }

        public byte[] UnwrapKey(JsonWebKey jkey, byte[] key)
        {
            var unwrappedTask = UnwrapKeyAsync(jkey, key);
            unwrappedTask.Wait();
            return unwrappedTask.Result;
        }

        /// <summary>
        /// Only get the key if we already know about it and have an identifier in the DB. 
        /// </summary>
        /// <param name="keyIdentifier">The identifier of the key.</param>
        /// <returns>The keybundle that contains the key and its identifier.</returns>
        public async Task<KeyBundle> GetKeyAsync(string keyIdentifier)
        {
            return await this.kv.GetKeyAsync(keyIdentifier);
        }

        /// <summary>
        /// Only get the key if we already know about it and have an identifier in the DB. 
        /// </summary>
        /// <param name="keyIdentifier">The identifier of the key.</param>
        /// <returns>The keybundle that contains the key and its identifier.</returns>
        public KeyBundle GetKey(string keyIdentifier)
        {
            var task = GetKeyAsync(keyIdentifier);
            task.Wait();
            return task.Result;
        }


        /// <summary>
        /// Only get the key if we already know about it and have an identifier in the DB. 
        /// </summary>
        /// <param name="name">The friendly name of the key.</param>
        /// <returns>The keybundle that contains the key and its identifier.</returns>
        public KeyBundle GetKeyByName(string name)
        {
            try
            {
                var task = this.kv.GetKeyAsync(this.VaultUri, name);
                task.Wait();
                return task.Result;
            }
            catch (AggregateException ax)
            {
                var ex = ax.InnerExceptions.FirstOrDefault() as KeyVaultClientException;
                if (ex != null && ex.Status == System.Net.HttpStatusCode.NotFound)
                    return null;
                throw ax.InnerExceptions.First();
            }
        }

        public async Task<KeyBundle> CreateKeyAsnc(string name)
        {
            string keyType = JsonWebKeyType.RsaHsm;
#if DEBUG
            keyType = JsonWebKeyType.Rsa;
#endif
            if (this.Test)
                keyType = JsonWebKeyType.Rsa;

            return await this.kv.CreateKeyAsync(this.VaultUri.ToString(), name, keyType);
        }
        public KeyBundle CreateKey(string name)
        {
            var task = CreateKeyAsnc(name);
            task.Wait();
            return task.Result;
        }

        public async Task DeleteKeyAsync(string keyIdentifier)
        {
            var bundle = await this.kv.GetKeyAsync(keyIdentifier);
            await this.kv.DeleteKeyAsync(bundle.KeyIdentifier.Vault, bundle.KeyIdentifier.Name);            
        }

        public void DeleteKey(string keyIdentifier)
        {
            var task = DeleteKeyAsync(keyIdentifier);
            task.Wait();
        }
    }
}
