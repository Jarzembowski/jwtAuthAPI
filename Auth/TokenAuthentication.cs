using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;
using System.Web.Http;
using System.Security.Principal;
using System.Web.Http.Controllers;
using System.Net;
using System.Runtime.CompilerServices;

namespace authServer.Auth
{
   public class AuthenticationFilter : AuthorizationFilterAttribute
   {

      /// <summary>
      /// read requested header and validated
      /// </summary>
      /// <param name="actionContext"></param>
      public override void OnAuthorization(HttpActionContext actionContext)
      {        
         var identity = FetchFromHeader(actionContext);
         if (identity != null)
         {
            if (JwtManager.ValidateToken(identity, out identity))
            {
               IPrincipal principal = new GenericPrincipal(new GenericIdentity(identity), null);
               Thread.CurrentPrincipal = principal;
               HttpContext.Current.User = principal;
            }
            else
            {
               actionContext.Response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
               return;
            }
         }
         else
         {
            actionContext.Response = new HttpResponseMessage(HttpStatusCode.BadRequest);
            return;
         }
         base.OnAuthorization(actionContext);
      }

      /// <summary>
      /// retrive header detail from the request 
      /// </summary>
      /// <param name="actionContext"></param>
      /// <returns></returns>
      private string FetchFromHeader(HttpActionContext actionContext)
      {
         string requestToken = null;

         var authRequest = actionContext.Request.Headers.Authorization;
         if (authRequest != null && !string.IsNullOrEmpty(authRequest.Scheme) && authRequest.Scheme == "Bearer")
            requestToken = authRequest.Parameter;

         return requestToken;
      }
   }
}