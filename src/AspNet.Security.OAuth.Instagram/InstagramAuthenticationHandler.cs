/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Instagram
{
    public class InstagramAuthenticationHandler : UserInfoOAuthHandler<InstagramAuthenticationOptions>
    {
        public InstagramAuthenticationHandler(
            [NotNull] IOptionsMonitor<InstagramAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, "access_token", tokens.AccessToken);

            if (Options.UseSignedRequests)
            {
                // Compute the HMAC256 signature.
                var signature = ComputeSignature(address);

                // Add the signature to the query string.
                address = QueryHelpers.AddQueryString(address, "sig", signature);
            }

            var request = new HttpRequestMessage(HttpMethod.Get, address);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return request;
        }

        protected virtual string ComputeSignature(string address)
        {
            using (var algorithm = new HMACSHA256(Encoding.UTF8.GetBytes(Options.ClientSecret)))
            {
                var query = new UriBuilder(address).Query;

                // Extract the parameters from the query string.
                var parameters = (from parameter in QueryHelpers.ParseQuery(query)
                                  orderby parameter.Key
                                  select $"{parameter.Key}={parameter.Value}").ToArray();
                Debug.Assert(parameters.Length != 0);

                // See https://www.instagram.com/developer/secure-api-requests/
                // for more information about the signature format.
                var bytes = Encoding.UTF8.GetBytes($"/users/self|{string.Join("|", parameters)}");

                // Compute the HMAC256 signature.
                var hash = algorithm.ComputeHash(bytes);

                // Convert the hash to its lowercased hexadecimal representation.
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }
    }
}