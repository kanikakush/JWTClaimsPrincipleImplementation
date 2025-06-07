using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Security.Claims;

namespace JWTClaimsPrincipleImplementation.CustomFilter
{
    public class MinimumRoleAuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        private readonly string[] _allowRoles;
        private static readonly Dictionary<string, int> RoleHierarchy = new()
        {
            { "User", 4 },
            { "Manager", 3 },
            { "Admin", 2 },
            { "SuperAdmin", 1   }
        };
        //current user = 2, allowed for manager, admin, superadmin
        public MinimumRoleAuthorizeAttribute(string[] minimunRole)
        {
            _allowRoles = minimunRole;
        }
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var userContext = context.HttpContext.User;
            if (userContext.Identity?.IsAuthenticated != true)
            {
                context.Result = new UnauthorizedResult(); //401 Unauthorized
                return;
            }
            var userCurrentRole = userContext.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role)?.Value;
            if(userCurrentRole is null || !_allowRoles.Contains(userCurrentRole, StringComparer.OrdinalIgnoreCase))
            {
                context.Result = new ForbidResult(); //403 Forbidden, user is authenticated but not authorized for this role
                return;
            }
            // allowRoles is not null or empty, check if the user has a role that meets the minimum requirement
        }
    }
}
