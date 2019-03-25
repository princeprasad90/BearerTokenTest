using Newtonsoft.Json.Linq;
using System;
using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Configuration;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace BearerToken
{
    #region Tokens
    public class TokenCheck : AuthorizeAttribute
    {
        public static string Response = string.Empty;
        public string User;
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            try
            {
                var TokenHead = HttpContext.Current.Request.Headers["Token"];
                if (!string.IsNullOrEmpty(TokenHead) && !string.IsNullOrWhiteSpace(TokenHead))
                {
                    var token = new Token(new TokenSet() { Type = 2 });// determine object creation from validate and keeep the static values
                    string[] splittoken = TokenHead.Trim().Split(' ');
                    if (!string.IsNullOrEmpty(WebConfigurationManager.AppSettings["TokenType"]))
                    {
                        if (splittoken[0] != WebConfigurationManager.AppSettings["TokenType"].Trim())
                            return false;
                        else
                            TokenHead = splittoken[1].Trim();
                    }
                    return token.ValidateToken(TokenHead.Trim(), out Response, User);
                }
            }
            catch (Exception ex)
            {
                return false;
            }
            return false;
        }
        protected override void HandleUnauthorizedRequest(HttpActionContext actionContext)
        {
            dynamic ResponseObj = new JObject();
            ResponseObj.Message = string.IsNullOrEmpty(Response) ? "Authorization has been denied for this request." : Response;
            string jsonString = Newtonsoft.Json.JsonConvert.SerializeObject(ResponseObj);
            actionContext.Response = new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.Unauthorized,
                Content = new StringContent(jsonString, System.Text.Encoding.UTF8, "application/json")
            };
        }
    }
    #endregion

}