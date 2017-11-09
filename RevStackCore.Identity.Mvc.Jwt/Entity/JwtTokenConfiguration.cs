using System;
namespace RevStackCore.Identity.Mvc.Jwt
{
    public class JwtTokenConfiguration
    {
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
    }
}
