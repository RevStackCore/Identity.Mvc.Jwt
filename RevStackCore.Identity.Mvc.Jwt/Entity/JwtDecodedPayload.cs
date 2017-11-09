using System;
namespace RevStackCore.Identity.Mvc.Jwt
{
    public class JwtDecodedPayload
    {
        public string Sub { get; set; }
        public string Jti { get; set; }
        public DateTime Exp { get; set; }
    }
}
