using System;
using System.Security.Cryptography;
using System.Text;

namespace PasswordSystem.Models
{
    public static class SHA512Helper
    {
        /// <summary>
        /// Алгорит шифрования 
        /// </summary>
        /// <param name="value">password</param>
        /// <param name="salt">random bytes array</param>
        /// <returns>hash</returns>
        public static string GetSHA512Code(this string value, string salt)
        {
            using (SHA512 crypt = new SHA512Managed())
            {
                return Convert.ToBase64String(crypt.ComputeHash(Encoding.UTF8.GetBytes(value + salt)));
            }
        }
    }
}
