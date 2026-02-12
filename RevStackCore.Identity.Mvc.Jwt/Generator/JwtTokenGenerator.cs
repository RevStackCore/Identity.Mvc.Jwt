using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace RevStackCore.Identity.Mvc.Jwt
{
    public class JwtTokenGenerator
    {
        public string Create(string secret, object payload)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
            var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

            var claims = new List<Claim>();
            foreach (var kvp in dict)
            {
                if (kvp.Value.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in kvp.Value.EnumerateArray())
                    {
                        claims.Add(new Claim(kvp.Key, item.ToString()));
                    }
                }
                else
                {
                    claims.Add(new Claim(kvp.Key, kvp.Value.ToString()));
                }
            }

            var token = new JwtSecurityToken(
                claims: claims,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
