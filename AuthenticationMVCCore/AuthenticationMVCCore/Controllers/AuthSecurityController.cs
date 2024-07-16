using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationMVCCore.Controllers
{
    // Implementing Authorization

    [Authorize(Roles = "Admin,Manager")]
    public class AuthSecurityController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        [Authorize(Roles ="Admin")]
        public IActionResult Settings()
        {
            return View();
        }
        [AllowAnonymous]
        public IActionResult About()
        {
            return View();
        }
        [AllowAnonymous]
        public IActionResult Contact()
        {
            return View();
        }
    }
}
