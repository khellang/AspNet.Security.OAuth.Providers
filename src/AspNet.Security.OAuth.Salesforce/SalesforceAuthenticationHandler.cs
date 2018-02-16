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

namespace AspNet.Security.OAuth.Salesforce
{
    public class SalesforceAuthenticationHandler : UserInfoOAuthHandler<SalesforceAuthenticationOptions>
    {
        public SalesforceAuthenticationHandler(
            [NotNull] IOptionsMonitor<SalesforceAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            // Note: unlike the other social providers, the userinfo endpoint is user-specific and can't be set globally.
            // For more information, see https://developer.salesforce.com/page/Digging_Deeper_into_OAuth_2.0_on_Force.com
            var request = new HttpRequestMessage(HttpMethod.Get, tokens.Response.Value<string>("id"));

            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return request;
        }
    }
}
