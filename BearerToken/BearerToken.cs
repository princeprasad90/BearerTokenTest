using Newtonsoft.Json.Linq;
using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Web.Configuration;

namespace BearerToken
{
    public class Token : CipherUtility
    {
        public static TokenSet _TokenSet;
        /// <summary>
        /// Set Timout and Algorithm Sample:  ExpirationTime = DateTime.Now.AddMinutes(30), Algorithm = new TripleDESCryptoServiceProvider() }
        /// Algorthims supported:  DESCryptoServiceProvider() ,RC2CryptoServiceProvider(),RijndaelManaged(),TripleDESCryptoServiceProvider()
        /// </summary>
        /// <param name="TokenSet"></param>
        public Token(TokenSet TokenSet)
        {
            _TokenSet = Attachref(TokenSet);
            _TokenSet.SaltKey = (!string.IsNullOrEmpty(WebConfigurationManager.AppSettings["SaltKey"])) ? WebConfigurationManager.AppSettings["SaltKey"] : "FqR6BwfbB";
        }
        public JObject GenerateToken(string username = "admin")
        {
            string filetime = DateTime.Now.ToFileTime().ToString();//apppend additional string 
            string content = username + "ß" + _TokenSet.ExpirationTime;//addd contents in token

            string xcode = CryptType.GetXcode(_TokenSet.Algorithm);

            Type t = _TokenSet.Algorithm.GetType();//using reflection as the using generics
            MethodInfo method = typeof(CipherUtility).GetMethod("Encrypt");
            MethodInfo generic = method.MakeGenericMethod(t);
            string GeneratedToken = (generic.Invoke(this, new object[] { content, _TokenSet.HashKey, _TokenSet.SaltKey }).ToString());

            GeneratedToken += "ß" + xcode + "ß" + filetime.Substring(filetime.Length - 6);
            dynamic result = new JObject();
            result.Token = CryptType.Base64Encode(GeneratedToken);
            if (!string.IsNullOrEmpty(WebConfigurationManager.AppSettings["TokenType"]))
                result.Type = WebConfigurationManager.AppSettings["TokenType"];
            result.GeneratedTime = DateTime.Now.ToString("dd-MM-yyyy hh:mm:ss tt");
            return result;
        }
        public bool ValidateToken(string token, out string Response, string username = "admin")
        {
            Response = "";
            try
            {

                string[] ParseToken = CryptType.Base64Decode(token).Split('ß');
                if (ParseToken[2].Length != 6)
                {
                    throw new Exception();
                }
                Type t = CryptType.GetCryptType(ParseToken[1]).GetType();
                MethodInfo method = typeof(CipherUtility).GetMethod("Decrypt");
                MethodInfo generic = method.MakeGenericMethod(t);
                string[] ParseStr = generic.Invoke(this, new object[] { ParseToken[0], _TokenSet.HashKey, _TokenSet.SaltKey }).ToString().Split('ß');
                if (ParseStr.Length == 2)
                {
                    if (!string.IsNullOrEmpty(username))
                    {
                        if (ParseStr[0] != username)
                            throw new Exception();
                    }
                    if (Convert.ToDateTime(ParseStr[1]) < DateTime.Now)
                    {
                        Response = "Authorization has been denied , Token Expired!";
                        throw new Exception();
                    }
                }
                else
                    throw new Exception();
            }
            catch (Exception ex)
            {
                Response = "Authorization has been denied , Token Not Valid!";
                return false;
            }
            return true;
        }
        private Func<TokenSet, TokenSet> Attachref = (set) =>
         {
             //  TokenSet sett = new TokenSet();
             if (set.ExpirationTime == null)
                 set.ExpirationTime = DateTime.Now.AddMinutes(30);
             if (set.Algorithm == null)
                 set.Algorithm = new TripleDESCryptoServiceProvider();
             if (set.HashKey == null)
             {
                 if (set.Type == 2)//2 means creating object in validate function,determine object creation
                 {
                     if (_TokenSet != null)
                     {
                         if (_TokenSet.HashKey != null)
                             set.HashKey = _TokenSet.HashKey;
                     }

                 }
                 if (set.HashKey == null)
                 {
                     var hmac = new HMACSHA1();
                     set.HashKey = Convert.ToBase64String(hmac.Key);
                 }
             }
             return set;
         };
    }
}