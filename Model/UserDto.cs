namespace JWTClaimsPrincipleImplementation.Model
{
    public class UserDto //user data transfer object
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? Role { get; set; } = string.Empty; // Default role if not specified
    }
}
