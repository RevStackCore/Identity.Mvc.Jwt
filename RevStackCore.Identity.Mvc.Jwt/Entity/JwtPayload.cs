using System;
using System.Collections.Generic;

namespace RevStackCore.Identity.Mvc.Jwt
{
    public class JwtPayload
    {
        public string Sub { get; set; }
        public double Exp { get; set; }
        public string Jti { get; set; }
        public string Aud { get; set; }
        public string Iss { get; set; }
        public IEnumerable<string> Roles { get; set; }
    }
}
