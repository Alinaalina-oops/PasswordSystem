using System;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace PasswordSystem.Models
{
    public class User
    {
        [Key]
        public string Login { get; set; }

        private string _salt;
        public string Salt
        {
            get
            {
                if (String.IsNullOrEmpty(_salt))
                {
                    byte[] random = new byte[30];// 15 symbols Unicode
                    RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
                    rng.GetBytes(random);
                    _salt = Convert.ToBase64String(random);
                    return _salt;
                }
                return _salt;
            }
            set
            {
                _salt = value;
            }
        }

        private string _hash;
        public string Hash {
            get
            {
                return _hash;
            }
            set
            {
                if (!String.IsNullOrEmpty(Login) && !String.IsNullOrEmpty(value))
                {
                    _hash = value.GetSHA512Code(Salt);
                }
                else
                {
                    throw new ArgumentException();
                }
            }
        }
    }
}
