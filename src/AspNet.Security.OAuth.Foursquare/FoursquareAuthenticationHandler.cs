/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
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
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Foursquare
{
    public class FoursquareAuthenticationHandler : UserInfoOAuthHandler<FoursquareAuthenticationOptions>
    {
        public FoursquareAuthenticationHandler(
            [NotNull] IOptionsMonitor<FoursquareAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            // See https://developer.foursquare.com/overview/versioning
            // for more information about the mandatory "v" and "m" parameters.
            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                ["m"] = "foursquare",
                ["v"] = Options.ApiVersion,
                ["oauth_token"] = tokens.AccessToken,
            });

            var request = new HttpRequestMessage(HttpMethod.Get, address);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return request;
        }

        protected override JObject GetUserData(JObject payload)
        {
            return payload.Value<JObject>("response")?.Value<JObject>("payload");
        }
    }
}
