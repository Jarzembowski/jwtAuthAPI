using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace authServer.Models.Requests
{
   public class UserRegister
   {
      public string email { get; set; }
      public string password { get; set; }
   }
}