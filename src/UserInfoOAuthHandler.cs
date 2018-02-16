/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth
{
    public abstract class UserInfoOAuthHandler<T> : OAuthHandler<T> where T : OAuthOptions, new()
    {
        protected UserInfoOAuthHandler(IOptionsMonitor<T> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var request = CreateUserInfoRequest(identity, properties, tokens);

            var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);

            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                    "returned a {Status} response with the following payload: {Headers} {Body}.",
                    /* Status: */ response.StatusCode,
                    /* Headers: */ response.Headers.ToString(),
                    /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving the user profile.");
            }

            var principal = new ClaimsPrincipal(identity);

            var payload = GetPayload(JObject.Parse(await response.Content.ReadAsStringAsync()));

            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload);

            var userData = GetUserData(payload);

            context.RunClaimActions(userData);

            await BeforeCreatingTicket(context);

            await Events.CreatingTicket(context);

            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }

        protected virtual HttpRequestMessage CreateUserInfoRequest(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            return request;
        }

        protected virtual JObject GetPayload(JObject content)
        {
            return content;
        }

        protected virtual JObject GetUserData(JObject payload)
        {
            return payload;
        }

        protected virtual Task BeforeCreatingTicket(OAuthCreatingTicketContext context)
        {
            return Task.CompletedTask;
        }
    }
}
