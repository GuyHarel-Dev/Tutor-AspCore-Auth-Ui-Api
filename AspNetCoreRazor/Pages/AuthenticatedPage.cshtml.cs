using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AspNetCoreRazor.Pages
{
    public class AuthenticatedModel : PageModel
    {
        private readonly ILogger<AuthenticatedModel> _logger;

        public AuthenticatedModel(ILogger<AuthenticatedModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
        }
    }

}
