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

namespace AspNet.Security.OAuth.Strava
{
    public class StravaAuthenticationHandler : UserInfoOAuthHandler<StravaAuthenticationOptions>
    {
        /// <summary>
        /// Authentication handler for Strava authentication
        /// </summary>
        public StravaAuthenticationHandler(
            [NotNull] IOptionsMonitor<StravaAuthenticationOptions> options,
            [NotNull] ILoggerFactory factory,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock) 
            : base(options, factory, encoder, clock)
        {
        }

        protected override HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            return request;
        }
    }
}
