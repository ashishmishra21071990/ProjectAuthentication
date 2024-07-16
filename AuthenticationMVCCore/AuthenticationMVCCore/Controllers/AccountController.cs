using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthenticationMVCCore.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(string userName,string Password)
        {
            if (string.IsNullOrEmpty(userName) && string.IsNullOrEmpty(Password))
            {
                return RedirectToAction("Login");
            }
            // Check the UserName and Password
            // Implement Cookie Authentication Logic
            ClaimsIdentity identity = null;
            bool isAuthenticated = false;
            if (userName == "Mohit" && Password == "password")
            {
                // Create the identity for Admin
                identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name,userName),
                    new Claim(ClaimTypes.Role,"Admin")
                }, CookieAuthenticationDefaults.AuthenticationScheme);
                isAuthenticated = true;
            }
            if (userName == "Ashish" && Password == "mishra")
            {
                //Create the identity for User
                identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name,userName),
                    new Claim(ClaimTypes.Role,"Manager")
                }, CookieAuthenticationDefaults.AuthenticationScheme);
                isAuthenticated = true;
            }
            if (userName == "Prateek" && Password == "kumar")
            {
                //Create the identity for User
                identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name,userName),
                    new Claim(ClaimTypes.Role,"User")
                }, CookieAuthenticationDefaults.AuthenticationScheme);
                isAuthenticated = true;
            }

            if (isAuthenticated)
            {
                var principal = new ClaimsPrincipal(identity);
                var login = HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                return RedirectToAction("Index", "AuthSecurity");
            }
            return View();
        }
        public IActionResult Logout()
        {
            var login = HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login");
        }
    }
}
