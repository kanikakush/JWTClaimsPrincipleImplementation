using JWTClaimsPrincipleImplementation.CustomFilter;
using JWTClaimsPrincipleImplementation.Entities;
using JWTClaimsPrincipleImplementation.Interface;
using JWTClaimsPrincipleImplementation.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTClaimsPrincipleImplementation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService authService;
        public AuthController(IAuthService authService)
        {
            this.authService = authService;
        }
        [MinimumRoleAuthorize(["Admin","SuperAdmin"])]
        [Idempotent(cacheDurationInMinutes: 5)]
        [HttpPost("register")]
        public async Task<ActionResult<User?>> Register(UserDto request)
        {
            var user = await authService.RegisterAsync(request);
            if (user is null)
                return BadRequest(new { Message = "User already exists" });

            return Ok(new { Message = "User registered successfully", User = user });
        }
        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto?>> Login(UserDto request)
        {
            var token = await authService.LoginAsync(request);
            if (token is null)
                return Unauthorized(new { Message = "Invalid username or password" });

            return Ok(new { Message = "Login successful", Token = token });
        }
        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto?>> RefreshToken(RefreshTokenRequestDto request)
        {
            var token = await authService.RefreshTokenAsync(request);
            if (token is null)
                return Unauthorized(new { Message = "Invalid/Expired Token" });

            return Ok(new { Message = "Login successful", Token = token });
        }
        [HttpGet("Auth-endpoint")]
        [Authorize]
        public ActionResult<string> AuthEndpoint()
        {
            return Ok("You are authenticated and authorized to access this endpoint.");
        }
        [HttpGet("Admin-endpoint")]
        [Authorize(Roles = "Admin")]
        public ActionResult<string> AdminEndpointCheck()
        {
            return Ok("You are authenticated and authorized to access this endpoint.");
        }
    }
}
