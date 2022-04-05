using Microsoft.IdentityModel.Tokens;
using RestAPIBaseNETFramework.DTOs;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace RestAPIBaseNETFramework.Controllers
{
    public class LoginController : ApiController
    {
        [HttpPost]
        [AllowAnonymous]
        public IHttpActionResult Login(UserLoginDTO userLoginDTO)
        {
            if (userLoginDTO == null)
                return BadRequest("User information is wrong.");
            else
                return Ok( new { token = GenerateTokenJWT(userLoginDTO) });
        }

        public static string GenerateTokenJWT(UserLoginDTO userLoginDTO)
        {
            // Getting configuration variables
            var _SecretKey = ConfigurationManager.AppSettings["SecretKey"];
            var _Issuer = ConfigurationManager.AppSettings["Issuer"];
            var _Audience = ConfigurationManager.AppSettings["Audience"];
            if (!Int32.TryParse(ConfigurationManager.AppSettings["Expires"], out int _Expires))
                _Expires = 24;

            var symmetricKey = Convert.FromBase64String(_SecretKey);
            var tokenHandler = new JwtSecurityTokenHandler();

            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                        {
                            new Claim(ClaimTypes.Name, Guid.NewGuid().ToString()),
                            new Claim("email", userLoginDTO.Email),
                            new Claim("name", userLoginDTO.Name),
                            new Claim("role", userLoginDTO.Rol)
                        }),

                Expires = now.AddMinutes(Convert.ToInt32(_Expires)),

                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(symmetricKey), SecurityAlgorithms.HmacSha256Signature)
            };

            SecurityToken securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(securityToken);

            return token;
        }

        private string GenerateTokenJWT2(UserLoginDTO userLoginDTO)
        {
            // Getting configuration variables
            var _SecretKey = ConfigurationManager.AppSettings["SecretKey"];
            var _Issuer = ConfigurationManager.AppSettings["Issuer"];
            var _Audience = ConfigurationManager.AppSettings["Audience"];
            if (!Int32.TryParse(ConfigurationManager.AppSettings["Expires"], out int _Expires))
                _Expires = 24;

            // Creating header
            var _symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_SecretKey));
            var _signingCredentials = new SigningCredentials(_symmetricSecurityKey, SecurityAlgorithms.HmacSha256);
            var _Header = new JwtHeader(_signingCredentials);

            // Creating claims
            var _Claims = new[] {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("email", userLoginDTO.Email),
                new Claim("name", userLoginDTO.Name),
                new Claim("role", userLoginDTO.Rol)
            };

            // Creating payload
            var _Payload = new JwtPayload(
                    issuer: _Issuer,
                    audience: _Audience,
                    claims: _Claims,
                    notBefore: DateTime.UtcNow,
                    // Expires in 24 hours.
                    expires: DateTime.UtcNow.AddHours(_Expires)
                );

            // Generating Token
            var _Token = new JwtSecurityToken(
                    _Header,
                    _Payload
                );

            return new JwtSecurityTokenHandler().WriteToken(_Token);
        }
    }
}