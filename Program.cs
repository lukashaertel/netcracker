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

    class KeccakOpen : Keccak
    {
        public KeccakOpen(KeccakBitType bitType) : base(bitType)
        {
        }

        public byte[] HashBytes(byte[] bytesToHash, int length)
        {
            base.Initialize((int)HashType.Keccak);
            base.Absorb(bytesToHash, 0, length);
            base.Partial(bytesToHash, 0, length);

            return base.Squeeze();
        }
    }

    class Program
    {
        static DateTime start;
        static int n;
        static int r;
        static int p;
        static int dkLen;

        static byte[] saltBytes;
        static byte[] cipherBytes;
        static byte[] macBytes;

        static bool RunWith(string password)
        {
            // Get scrypt hash from given values.
            var scrypt = ScryptUtil.Scrypt(password, saltBytes, n, r, p, dkLen);

            // Get data for hashing. Fill with concatenation.
            var inputLength = 16 + cipherBytes.Length;
            var input = new byte[inputLength];
            Buffer.BlockCopy(scrypt, 16, input, 0, 16);
            Buffer.BlockCopy(cipherBytes, 0, input, 16, cipherBytes.Length);

            // Get hash value of data.
            var hasher = new KeccakOpen(KeccakBitType.K256);
            var hash = hasher.HashBytes(input, inputLength);

            // Return true if equal length and sequence equal.
            return macBytes.Length == hash.Length && macBytes.AsSpan().SequenceEqual(hash);
        }

        static async Task RunAll(string walletPath, string wordlistPath)
        {
            // Mark start.
            start = DateTime.Now;

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
            n = wallet.Crypto.KdfParams.N;
            r = wallet.Crypto.KdfParams.R;
            p = wallet.Crypto.KdfParams.P;
            dkLen = wallet.Crypto.KdfParams.DkLen;

            // Get bytes from hexadecimal values.
            saltBytes = Convert.FromHexString(wallet.Crypto.KdfParams.Salt);
            cipherBytes = Convert.FromHexString(wallet.Crypto.CipherText);
            macBytes = Convert.FromHexString(wallet.Crypto.Mac);

            // Get all words into large array.
            var words = await File.ReadAllLinesAsync(wordlistPath);

            // Run on all words.
            Parallel.For(0, words.Length,  i =>
            {
                // Get word.
                var word = words[i];
                // If pass successful with this word, print result and exit program.
                if (RunWith(word))
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
