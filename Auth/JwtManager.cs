using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Configuration;

namespace authServer.Auth
{
   public class JwtManager
   {
      public JwtManager()
      {

      }

      private static string Secret = WebConfigurationManager.AppSettings["JwtManagerKey"];

      public static string generateToken(string username, int expireDays = 100)
      {
         var symmetricKey = Convert.FromBase64String(Secret);
         var tokenHandler = new JwtSecurityTokenHandler();

         var now = DateTime.UtcNow;
         var tokenDescriptor = new SecurityTokenDescriptor
         {
            Subject = new ClaimsIdentity(new[]
                     {
                        new Claim(ClaimTypes.Name, username)
                    }),

            Expires = now.AddDays(Convert.ToInt32(expireDays)),

            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
         };

         var stoken = tokenHandler.CreateToken(tokenDescriptor);
         var token = tokenHandler.WriteToken(stoken);

         return token;
      }

      public static bool ValidateToken(string token, out string username)
      {
         username = null;

         var simplePrinciple = JwtManager.GetPrincipal(token);
         var identity = simplePrinciple.Identity as ClaimsIdentity;

         if (identity == null)
            return false;

         if (!identity.IsAuthenticated)
            return false;

         var usernameClaim = identity.FindFirst(ClaimTypes.Name);
         username = usernameClaim?.Value;

         if (string.IsNullOrEmpty(username))
            return false;

         return true;
      }

      public static ClaimsPrincipal GetPrincipal(string token)
      {
         try
         {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            if (jwtToken == null)
               return null;

            var symmetricKey = Convert.FromBase64String(Secret);

            var validationParameters = new TokenValidationParameters()
            {
               RequireExpirationTime = true,
               ValidateIssuer = false,
               ValidateAudience = false,
               IssuerSigningKey = new SymmetricSecurityKey(symmetricKey)
            };

            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, validationParameters, out securityToken);

            return principal;
         }

         catch (Exception e)
         {
            Console.WriteLine(e);
            return null;
         }
      }

   }
}