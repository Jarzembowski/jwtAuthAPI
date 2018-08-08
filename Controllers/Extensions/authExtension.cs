using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security.Cryptography;
using System.Text;

namespace authServer.Controllers.Extensions
{
   public class authExtension
   {
      public static string getPasswordHash(string password)
      {
         if (String.IsNullOrEmpty(password))
            return String.Empty;
         using (var sha = new SHA256Managed())
         {
            byte[] textData = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] hash = sha.ComputeHash(textData);
            return BitConverter.ToString(hash).Replace("-", String.Empty);
         }
      }

      public static string getUserCode(string email)
      {
         var userCode = CalculateMD5Hash(email);
         return userCode;
      }

      internal static string  CalculateMD5Hash(string input)
      {         
         MD5 md5 = System.Security.Cryptography.MD5.Create();
         byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
         byte[] hash = md5.ComputeHash(inputBytes);
         
         StringBuilder sb = new StringBuilder();
         for (int i = 0; i < hash.Length; i++)

         {
            sb.Append(hash[i].ToString("X2"));
         }
         return sb.ToString();
      }

   }
}