using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace mincrypt
{
    public class Person
    {

        private RSACryptoServiceProvider RSA;
        private ECDiffieHellmanCng ECDH;
        private SHA256CryptoServiceProvider SHA2;
        private byte[] symmettricKey;

        public Person()
        {
            // Generate a 2048-bit RSA public-private pair.
            RSA = new RSACryptoServiceProvider(2048);
            SHA2 = new SHA256CryptoServiceProvider();

            // Setup an ECDH implementation.
            ECDH = new ECDiffieHellmanCng();
            ECDH.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            ECDH.HashAlgorithm = CngAlgorithm.Sha256;
        }

        public RSAParameters GetPublicRSAParameters()
        {
            return RSA.ExportParameters(false);
        }

        public byte[] GetSignedDHPublicKey()
        {
            return RSA.SignData(GetDHPublicKey().ToByteArray(), SHA2);
        }

        public ECDiffieHellmanPublicKey GetDHPublicKey()
        {
            return ECDH.PublicKey;
        }

        public bool InitaliseSymmettricKey(ECDiffieHellmanPublicKey otherPartyPublicKey, byte[] signedPublicKey, RSAParameters otherPartyRSAPublicKey)
        {
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.ImportParameters(otherPartyRSAPublicKey);
            if(csp.VerifyData(otherPartyPublicKey.ToByteArray(), SHA2, signedPublicKey))
            {
                symmettricKey = ECDH.DeriveKeyMaterial(otherPartyPublicKey);
                return true;
            }
            else
            {
                return false;
            }
        }

        public void Encrypt(string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = symmettricKey;
                iv = aes.IV;

                // Encrypt the message
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                }
            }
        }

        public string Decrypt(byte[] encryptedMessage, byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = symmettricKey;
                aes.IV = iv;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();
                        return Encoding.UTF8.GetString(plaintext.ToArray());
                    }
                }
            }
        }
    }
}
