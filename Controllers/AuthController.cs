using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using authServer.Models;
using authServer.Models.Requests;
using authServer.Controllers.Extensions;
using authServer.Auth;
using System.Web;

namespace authServer.Controllers
{
   [RoutePrefix("auth/api")]
   public class AuthController : ApiController
   {
      private readonly authEntities _db;

      public AuthController()
      {
         _db = new authEntities();
      }

      [Route("register")]
      [HttpPost]
      public IHttpActionResult PostRegister(UserRegister userRequest)
      {

         var userExists = _db.userAuth.Where(u => u.email.ToUpper() == userRequest.email.ToUpper()).FirstOrDefault();
         if (userExists != null)
            return BadRequest("User already exists");

         var user = new userAuth
         {
            email = userRequest.email.ToLower(),
            passwordHash = authExtension.getPasswordHash(userRequest.password),
            cod = authExtension.getUserCode(userRequest.email)
         };

         _db.userAuth.Add(user);
         _db.SaveChanges();

         //Generate TOKEN
         string token = JwtManager.generateToken(user.email, 150);

         return Ok(token);
      }


      [Route("validate")]
      [HttpGet]
      public IHttpActionResult GetValidate(string token)
      {
         string userName;
         JwtManager.ValidateToken(token, out userName);

         return Ok(userName);
      }

      [AuthenticationFilter]
      [Route("user/{id}")]
      [HttpGet]
      public IHttpActionResult GetUser(int id)
      {
         var userIdentity = HttpContext.Current.User;
         var userId = userIdentity.Identity.Name;

         var user = _db.userAuth.Where(u => u.id == id).FirstOrDefault();
         if (user == null)
            return BadRequest("Not found.");

         return Ok(user);
      }


   }
}
