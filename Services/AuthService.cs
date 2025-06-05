using JWTClaimsPrincipleImplementation.Data;
using JWTClaimsPrincipleImplementation.Entities;
using JWTClaimsPrincipleImplementation.Interface;
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
    public class AuthService: IAuthService // Assuming IAuthService is defined in Interface/IAuthService.cs
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
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();
            return user;
        }
        public async Task<string?> LoginAsync(UserDto request)
        {
            User? user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
                return null;
            //passswordHasher has proprty VerifyHashedPassword as we can't convert it in simple string
            var passwordVerificationResult = new PasswordHasher<User>()
                .VerifyHashedPassword(user, user.PasswordHash, request.Password);
            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                return null;
            }
            //instead of returning user , you can return a JWT token here
            string token = CreateToken(user);
            //return Ok(new { Message = "Login successful", User = user });
            return token;
        }
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role ?? "Admin") // Default role if not set
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
