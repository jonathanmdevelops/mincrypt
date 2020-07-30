using System;
using System.Security.Cryptography;
using System.Text;
using mincrypt;

namespace MinCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            Person alice = new Person();
            Person bob = new Person();

            Console.WriteLine("Exchanging keys...");

            // The DH public key is signed.
            byte[] aliceSignedDHPublicKey = alice.GetSignedDHPublicKey();
            byte[] bobSignedDHPublicKey = bob.GetSignedDHPublicKey();

            // The DH public key is verified and then used to derive a symmettric key for message encryption.
            bool aliceInitialised = alice.InitaliseSymmettricKey(bob.GetDHPublicKey(), bobSignedDHPublicKey, bob.GetPublicRSAParameters());
            bool bobInitialised = bob.InitaliseSymmettricKey(alice.GetDHPublicKey(), aliceSignedDHPublicKey, alice.GetPublicRSAParameters());

            if (!aliceInitialised || !bobInitialised)
            {
                Console.WriteLine("Key exchange and verification failed.");
                Console.ReadLine();
                return;
            }
            Console.WriteLine("Keys exchanged.");

            byte[] encryptedMessage = null;
            byte[] iv = null;

            Console.Write("Enter a message for Alice to send: ");
            var originalMessage = Console.ReadLine();
            Console.WriteLine("Sending message \"" + originalMessage + "\".");

            alice.Encrypt(originalMessage, out encryptedMessage, out iv);
            Console.WriteLine("Alice sent \"" + Encoding.Default.GetString(encryptedMessage) + "\".");

            string decryptedMessage = bob.Decrypt(encryptedMessage, iv);
            Console.WriteLine("Bob decrypted \"" + decryptedMessage + "\".");
        }
    }
}
