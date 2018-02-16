/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Automatic
{
    public class AutomaticAuthenticationHandler : UserInfoOAuthHandler<AutomaticAuthenticationOptions>
    {
        public AutomaticAuthenticationHandler(
            [NotNull] IOptionsMonitor<AutomaticAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            // Note: the redirect_uri parameter is not allowed by Automatic and MUST NOT be sent.
            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, new Dictionary<string, string>
            {
                ["client_id"] = Options.ClientId,
                ["response_type"] = "code",
                ["scope"] = FormatScope(),
                ["state"] = Options.StateDataFormat.Protect(properties)
            });
        }
    }
}