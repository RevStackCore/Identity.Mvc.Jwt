using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace RevStackCore.Identity.Mvc.Jwt
{
    public static class JwtExtensions
    {
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        public static string ToJwtToken<TKey>(this IIdentityUser<TKey> user, string secret, string issuer, string audience, DateTime? expires)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
               new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(issuer, audience, claims, expires: expires, signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public static ClaimsPrincipal GetPrincipleFromExpiredToken(this string expiredToken, string secret, bool validateAudience=false, bool validateIssuer=false)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = validateAudience,
                ValidateIssuer = validateIssuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                ValidateLifetime = false //ignore token's expiration date
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(expiredToken, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                return null;

            return principal;
        }

        public static JwtPayload ToJwtDecodedPayload(this HttpRequest request, string secret)
        {
            bool result = request.Headers.TryGetValue("Authorization", out var headers);
            if (!result)
            {
                return null;
            }
            string authHeader = headers.FirstOrDefault();
            var authBits = authHeader.Split(' ');
            if (authBits.Length != 2)
            {
                return null;
            }
            if (!authBits[0].ToLowerInvariant().Equals("bearer"))
            {
                return null;
            }
            string token = authBits[1];
            return ReadJwtPayload(token);
        }

        public static JwtPayload ToJwtDecodedPayload(this string token, string secret)
        {
            return ReadJwtPayload(token);
        }

        public static T ToJwtDecodedPayload<T>(this string token, string secret)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var json = System.Text.Json.JsonSerializer.Serialize(jwtToken.Payload);
            return System.Text.Json.JsonSerializer.Deserialize<T>(json, new System.Text.Json.JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
        }

        public static double ToUnixEpochExpiration(this DateTime src)
        {
            var unixEpoch = UnixEpoch;
            return Math.Round((src - unixEpoch).TotalSeconds);
        }

        private static JwtPayload ReadJwtPayload(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            var payload = jwtToken.Payload;

            return new JwtPayload
            {
                Sub = payload.Sub,
                Exp = payload.Expiration.HasValue ? (double)payload.Expiration.Value : 0,
                Jti = payload.Jti,
                Aud = payload.Aud?.FirstOrDefault(),
                Iss = payload.Iss,
                Roles = jwtToken.Claims
                    .Where(c => c.Type == "roles" || c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
                    .ToList()
            };
        }
    }
}
