using System;
using System.Buffers;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Norgerman.Cryptography.Scrypt;
using SHA3Core.Enums;
using SHA3Core.Keccak;
using SHA3Core.SHA3;

namespace netcracker
{
    class KdfParams
    {
        public int N { get; set; }
        public int R { get; set; }
        public int P { get; set; }
        public int DkLen { get; set; }
        public string Salt { get; set; }
    }

    class Crypto
    {
        public string Kdf { get; set; }
        public KdfParams KdfParams { get; set; }
        public string Cipher { get; set; }
        public string CipherText { get; set; }
        public string Mac { get; set; }
    }

    class Wallet
    {
        public Crypto Crypto { get; set; }
    }

    class Program
    {
        static DateTime start;

        static bool RunWith(string password, byte[] saltBytes, int n, int r, int p, int dkLen, byte[] cipherBytes, byte[] mac)
        {
            // Get scrypt hash from given values.
            var scrypt = ScryptUtil.Scrypt(password, saltBytes, n, r, p, dkLen);
            
            // Get data for hashing.
            var input = new byte[16 + cipherBytes.Length];
            Buffer.BlockCopy(scrypt, 16, input, 0, 16);
            Buffer.BlockCopy(cipherBytes, 0, input, 16, cipherBytes.Length);

            // Get SHA3/KECCAK value of data.
            var sha3 = new Keccak(KeccakBitType.K256);
            var hash = Convert.FromHexString(sha3.Hash(input));

            // No.
            if (mac.Length != hash.Length)
                return false;

            // If any not equal, return false.
            for (var i = 0; i < mac.Length; i++)
                if (mac[i] != hash[i])
                    return false;

            // All equal, return true.
            return true;
        }

        static async Task RunAll(string walletPath, string wordlistPath)
        {
            // Mark start.
            start = DateTime.Now;

            // Get all words into large array.
            var words = await File.ReadAllLinesAsync(wordlistPath);

            // Get wallet and parse it.
            using var walletStream = File.OpenRead(walletPath);
            var wallet = await JsonSerializer.DeserializeAsync<Wallet>(walletStream, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            // Assert correct state.
            if (wallet.Crypto.Cipher != "aes-128-ctr")
                throw new ArgumentException("Incompatible cipher");
            if (wallet.Crypto.Kdf != "scrypt")
                throw new ArgumentException("Incompatible KDF");

            // Get parameters.
            var n = wallet.Crypto.KdfParams.N;
            var r = wallet.Crypto.KdfParams.R;
            var p = wallet.Crypto.KdfParams.P;
            var salt = wallet.Crypto.KdfParams.Salt;
            var dkLen = wallet.Crypto.KdfParams.DkLen;
            var cipherText = wallet.Crypto.CipherText;
            var mac = wallet.Crypto.Mac;

            // Get bytes from hexadecimal values.
            var saltBytes = Convert.FromHexString(salt);
            var cipherBytes = Convert.FromHexString(cipherText);
            var macBytes = Convert.FromHexString(mac);

            // Run on all words.
            Parallel.ForEach(words, word =>
            {
                // If pass successful with this word, print result and exit program.
                if (RunWith(word, saltBytes, n, r, p, dkLen, cipherBytes, macBytes))
                {
                    Console.WriteLine("Run for {0}", DateTime.Now - start);
                    Console.WriteLine("Password: " + word);
                    Environment.Exit(0);
                }
            });

            // Exit not called from password finding, mark as no result.
            Console.WriteLine("Run for  {0}", DateTime.Now - start);
            Console.WriteLine("No password found.");
        }

        static async Task Main(string[] args)
        {
            // Assert program arguments given.
            if (args.Length != 2)
            {
                await Console.Error.WriteLineAsync("Requires wallet path and wordlist path.");
                Environment.Exit(1);
                return;
            }

            // Get values.
            var walletPath = args[0];
            var wordlistPath = args[1];

            // Run all.
            await RunAll(walletPath, wordlistPath);
        }
    }
}
