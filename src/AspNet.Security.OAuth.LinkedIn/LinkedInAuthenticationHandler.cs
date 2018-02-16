/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.LinkedIn
{
    public class LinkedInAuthenticationHandler : UserInfoOAuthHandler<LinkedInAuthenticationOptions>
    {
        public LinkedInAuthenticationHandler(
            [NotNull] IOptionsMonitor<LinkedInAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var address = Options.UserInformationEndpoint;

            // If at least one field is specified,
            // append the fields to the endpoint URL.
            if (Options.Fields.Count != 0)
            {
                address = address.Insert(address.LastIndexOf("~") + 1, $":({ string.Join(",", Options.Fields)})");
            }

            var request = new HttpRequestMessage(HttpMethod.Get, address);

            request.Headers.Add("x-li-format", "json");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            return request;
        }
    }
}