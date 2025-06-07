namespace JWTClaimsPrincipleImplementation.Model
{
    public class TokenResponseDto // This class represents the response containing the token and user information. data transfer object (DTO)
    {
        public string AccessToken { get; set; } = string.Empty;// The JWT token string
        public string RefreshUser { get; set; } = string.Empty;// The user information associated with the token
    }
}
