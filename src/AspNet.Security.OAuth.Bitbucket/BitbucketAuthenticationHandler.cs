/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Bitbucket
{
    public class BitbucketAuthenticationHandler : UserInfoOAuthHandler<BitbucketAuthenticationOptions>
    {
        public BitbucketAuthenticationHandler(
            [NotNull] IOptionsMonitor<BitbucketAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            return request;
        }

        protected override async Task BeforeCreatingTicket(OAuthCreatingTicketContext context)
        {
            // When the email address is not public, retrieve it from
            // the emails endpoint if the user:email scope is specified.
            if (!string.IsNullOrEmpty(Options.UserEmailsEndpoint) &&
                !context.Identity.HasClaim(claim => claim.Type == ClaimTypes.Email) && Options.Scope.Contains("email"))
            {
                var address = await GetEmailAsync(context.TokenResponse);
                if (!string.IsNullOrEmpty(address))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, address, ClaimValueTypes.String, Options.ClaimsIssuer));
                }
            }
        }

        protected virtual async Task<string> GetEmailAsync([NotNull] OAuthTokenResponse tokens)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, Options.UserEmailsEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            // Failed requests shouldn't cause an error: in this case, return null to indicate that the email address cannot be retrieved.
            var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogWarning("An error occurred while retrieving the email address associated with the logged in user: " +
                                  "the remote server returned a {Status} response with the following payload: {Headers} {Body}.",
                                  /* Status: */ response.StatusCode,
                                  /* Headers: */ response.Headers.ToString(),
                                  /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            return (from address in payload.Value<JArray>("values")
                    where address.Value<bool>("is_primary")
                    select address.Value<string>("email")).FirstOrDefault();
        }
    }
}
