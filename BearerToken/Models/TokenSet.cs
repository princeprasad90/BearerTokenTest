using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace BearerToken
{
    public class TokenSet
    {
        public string HashKey { get; set; }
        public string SaltKey { get; set; }
        public SymmetricAlgorithm Algorithm { get; set; }
        public DateTime? ExpirationTime { get; set; }
        public int Type { get; set; }
    }

    public class CryptType
    {
        private static Dictionary<string, SymmetricAlgorithm> types = new Dictionary<string, SymmetricAlgorithm>()
        {
            {"C8iK", new AesCryptoServiceProvider() },
            {"LTQ9",  new DESCryptoServiceProvider()},
            {"EhtpT",  new RC2CryptoServiceProvider()},
            {"3hTx",  new RijndaelManaged()},
            {"Zg0Oq",  new TripleDESCryptoServiceProvider()},
        };
        public static Func<string, SymmetricAlgorithm> GetCryptType = (A) => { return types.FirstOrDefault(x => x.Key == A).Value; };
        public static Func<SymmetricAlgorithm, string> GetXcode = (A) => { return types.FirstOrDefault(x => x.Value.ToString() == A.ToString()).Key; };
        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }
        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }      
    }
}