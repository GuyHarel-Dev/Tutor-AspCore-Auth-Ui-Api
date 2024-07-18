using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AspNetCoreRazor.Pages
{
    public class LogoutModel : PageModel
    {
        public void OnGet()
        {
            HttpContext.SignOutAsync();
        }
    }
}
