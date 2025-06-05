using JWTClaimsPrincipleImplementation.Entities;
using JWTClaimsPrincipleImplementation.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTClaimsPrincipleImplementation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static User user = new(); // This should be replaced with a proper user repository or service
        private readonly IConfiguration configuration;
        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        [HttpPost("register")]
        public ActionResult<User?> Register(UserDto request)
        {
            user.Username = request.Username;
            user.PasswordHash = new PasswordHasher<User>()
                .HashPassword(user, request.Password);
            return Ok(new { Message = "User registered successfully", User = user });
        }
        [HttpPost("login")]
        public ActionResult<string?> Login(UserDto request)
        {
            if (user.Username != request.Username)
            {
                return Unauthorized(new { Message = "Invalid username or password" });
            }
            //passswordHasher has proprty VerifyHashedPassword as we can't convert it in simple string
            var passwordVerificationResult = new PasswordHasher<User>()
                .VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                return Unauthorized(new { Message = "Invalid username or password" });
            }
            //instead of returning user , you can return a JWT token here
            string token = CreateToken(user);
            //return Ok(new { Message = "Login successful", User = user });
            return Ok(new { Message = "Login successful", Token = token });
        }
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                // Add other claims as needed
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),
                audience: configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1), // Token expiration time
                signingCredentials: creds
                );
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
