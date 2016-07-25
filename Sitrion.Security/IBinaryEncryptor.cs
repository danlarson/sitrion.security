namespace Sitrion.Security
{
    public interface IBinaryEncryptor
    {
        byte[] DecryptBytes(byte[] encryptedValue);
        byte[] EncryptBytes(byte[] data);
    }
}