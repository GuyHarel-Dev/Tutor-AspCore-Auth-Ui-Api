using Microsoft.AspNetCore.Http;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace AspNetInfra
{
    public static class HttpHelper
    {
        public static string JsonToString(object obj)
        {
            return JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });
        }
        public static string RequestToString(HttpRequest request)
        {
            var desc = new HttpDesc();

            desc.Url = $"{request.Scheme}://{request.Host}{request.Path}{request.QueryString}";

            // Query String
            if (request.QueryString.HasValue)
            {
                desc.QueryStrings.AddRange(request.QueryString.Value.Split("\r").ToList());
            }

            // Headers
            foreach (var header in request.Headers)
            {
                desc.Headers.Add($"{header.Key}: {header.Value}");
            }

            // Body
            string body = string.Empty;
            request.EnableBuffering();
            using (var reader = new StreamReader(request.Body, Encoding.UTF8, true, 1024, leaveOpen: true))
            {
                body = reader.ReadToEndAsync().Result;
                request.Body.Position = 0;
            }

            if (!string.IsNullOrEmpty(body)) {
                desc.Body.AddRange(body.Split("\u0026"));

            }

            return JsonSerializer.Serialize(desc, new JsonSerializerOptions { WriteIndented = true});
        }
    }

    public class HttpDesc
    {
        public string Url { get; set; }
        public List<string> Headers { get; set; } = new List<string>();
        public List<string> QueryStrings { get; set; } = new List<string>();
        public List<string> Body { get; set; } = new List<string>();
    }

}
