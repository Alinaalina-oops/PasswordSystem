using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace PasswordSystem
{
    public class AuthOptions
    {
        public const string ISSUER = "MyPasswordSystem";
        public const string REFRESH_ISSUER = "REFRESH_ISSUER";
        public const string AUDIENCE = "MyPasswordSystemSwagger";
        public const string AUDIENCE_FOR_REFRESH = "MyPasswordForRefresh";

        const string KEY = "mysupersecret_secretkey!123";
        public const int LIFETIME = 60;
        public static SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(KEY));
        }
    }
}
