using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using PasswordSystem;
using PasswordSystem.Db;
using PasswordSystem.Models;

namespace PasswordSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly MyDbContext _context;

        public UsersController(MyDbContext context)
        {
            _context = context;
        }

        [HttpPost("registrate")]
        public IActionResult Registrate(string login, string password)
        {
            
            if (_context.Users.FirstOrDefault(u => u.Login.Equals(login)) != null)
                return BadRequest(400);
            try
            {
                User user = new User();
                user.Login = login;
                user.Hash = password;
                _context.Users.Add(user);
                _context.SaveChanges();
                return Ok(201);
            }
            catch (Exception)
            {
                return BadRequest(400);
            }
        }

        [HttpPost("auth")]
        public IActionResult Auth(string login, string password)
        {
            
            var localUser = _context.Users.FirstOrDefault(user => user.Login.Equals(login));
            if (localUser == null)
            {
                return BadRequest(401);
            }
            User user = new User();
            user.Login = login;
            user.Salt = localUser.Salt;
            user.Hash = password;
            if (_context.Users.FirstOrDefault(u => user.Login.Equals(u.Login) && user.Hash.Equals(u.Hash)) != null)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Login),
                    new Claim(ClaimTypes.Name, user.Login),
                };
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                var now = DateTime.UtcNow;
                var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        notBefore: now,
                        claims: claimsIdentity.Claims,
                        expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                var jwtRefresh = new JwtSecurityToken(
                    issuer: AuthOptions.REFRESH_ISSUER,
                    audience: AuthOptions.AUDIENCE_FOR_REFRESH,
                    notBefore: now,
                    claims: claimsIdentity.Claims.Where(item => item.Type == ClaimTypes.NameIdentifier),
                    expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                string refreshEncodeJwt = new JwtSecurityTokenHandler().WriteToken(jwtRefresh);

                var responce = new
                {
                    access_token = encodedJwt,
                    request_token = refreshEncodeJwt
                };
                HttpContext.Response.Cookies.Append("access_token", encodedJwt);
                HttpContext.Response.Cookies.Append("request_token", refreshEncodeJwt);
                return Ok(responce);
            }
            else
            {
                return BadRequest(401);
            }
        }

        [HttpPost("refresh")]
        public IActionResult Refresh()
        {
            try
            {
                string token = HttpContext.Request.Cookies.FirstOrDefault(item => item.Key.Equals("request_token")).Value;
                var jwtHandler = new JwtSecurityTokenHandler();
                var tokenValidParameters = new TokenValidationParameters()
                {
                    ValidIssuer = AuthOptions.REFRESH_ISSUER,
                    ValidAudience = AuthOptions.AUDIENCE_FOR_REFRESH,
                    IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };
                var tokenContent = jwtHandler.ValidateToken(token, tokenValidParameters, out var _);
                if (tokenContent == null)
                {
                    throw new Exception();
                }
                var login = tokenContent.Claims.FirstOrDefault(item => item.Type.Equals(ClaimTypes.NameIdentifier)).Value;
                
                List<Claim> claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, login),
                    new Claim(ClaimTypes.Name, login),
                };
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                var now = DateTime.UtcNow;
                var jwt = new JwtSecurityToken(
                        issuer: AuthOptions.ISSUER,
                        audience: AuthOptions.AUDIENCE,
                        notBefore: now,
                        claims: claimsIdentity.Claims,
                        expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

                var jwtRefresh = new JwtSecurityToken(
                    issuer: AuthOptions.REFRESH_ISSUER,
                    audience: AuthOptions.AUDIENCE_FOR_REFRESH,
                    notBefore: now,
                    claims: claimsIdentity.Claims.Where(item => item.Type == ClaimTypes.NameIdentifier),
                    expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
                string refreshEncodeJwt = new JwtSecurityTokenHandler().WriteToken(jwtRefresh);

                HttpContext.Response.Cookies.Append("access_token", encodedJwt);
                HttpContext.Response.Cookies.Append("request_token", refreshEncodeJwt);
                return Ok(200);
            }
            catch (Exception )
            {
                return BadRequest(403);
            }
        }
    }
}
