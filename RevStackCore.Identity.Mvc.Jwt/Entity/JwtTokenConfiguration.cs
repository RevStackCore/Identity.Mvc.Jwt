using System;

namespace RevStackCore.Identity.Mvc.Jwt
{
    public class JwtTokenConfiguration
    {
        public string Secret { get; set; }
        public JwtPayload Payload { get; set; }
    }
}
