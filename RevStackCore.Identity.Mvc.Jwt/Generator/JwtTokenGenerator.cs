using System;
using JWT;
using JWT.Algorithms;
using JWT.Serializers;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace RevStackCore.Identity.Mvc.Jwt
{
    public class JwtTokenGenerator
    {
        public string Create(string secret, object payload)
        {
            IJwtAlgorithm algorithm = new HMACSHA256Algorithm();
            JsonSerializer customJsonSerializer = new JsonSerializer
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver(),
            };
            IJsonSerializer serializer = new JsonNetSerializer(customJsonSerializer);
            IBase64UrlEncoder urlEncoder = new JwtBase64UrlEncoder();
            IJwtEncoder encoder = new JwtEncoder(algorithm, serializer, urlEncoder);
            var token = encoder.Encode(payload, secret);
            return token;
        }
    }
}
