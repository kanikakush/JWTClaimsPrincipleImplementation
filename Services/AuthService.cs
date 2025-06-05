using JWTClaimsPrincipleImplementation.Data;
using JWTClaimsPrincipleImplementation.Entities;
using JWTClaimsPrincipleImplementation.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTClaimsPrincipleImplementation.Services
{
    public class AuthService
    {
        private readonly IConfiguration configuration;
        private readonly MyDbContext context; // Assuming you have a DbContext for database operations
        public AuthService(IConfiguration configuration, MyDbContext context)
        {
            this.configuration = configuration;
            this.context = context;
        }
        public async Task<User?> RegisterAsync(UserDto request)
        {
            if(await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return null; // User already exists
            }
            var user = new User
            {
                Username = request.Username,
                PasswordHash = new PasswordHasher<User>()
                    .HashPassword(null, request.Password) // Hashing the password
            };
            user.Username = request.Username;
            user.PasswordHash = new PasswordHasher<User>()
                .HashPassword(user, request.Password);
            return user;
        }
        public async Task<User?> Login(UserDto request)
        {
            User? user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
                return null;
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
