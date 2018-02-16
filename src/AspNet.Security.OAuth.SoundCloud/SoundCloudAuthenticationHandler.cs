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
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.SoundCloud
{
    public class SoundCloudAuthenticationHandler : UserInfoOAuthHandler<SoundCloudAuthenticationOptions>
    {
        public SoundCloudAuthenticationHandler(
            [NotNull] IOptionsMonitor<SoundCloudAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, "oauth_token", tokens.AccessToken);

            var request = new HttpRequestMessage(HttpMethod.Get, address);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return request;
        }
    }
}
