using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Http
{
    public class DigestAuthMessageHandler : DelegatingHandler
    {
        private string _username;
        private string _password;

        private static readonly ConcurrentDictionary<string, AuthorizationParameter> _authorizationCache = new ConcurrentDictionary<string, AuthorizationParameter>();

        public DigestAuthMessageHandler(HttpMessageHandler innerHandler, string username, string password)
            : base(innerHandler)
        {
            _username = username;
            _password = password;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            AuthorizationParameter authorizationParameter;

            if (!TryGetCachedAuthorizationParameterByUri(request.RequestUri, out authorizationParameter))
            {
                // the AuthorizationParameter ist not in the cache
                var response = await base.SendAsync(request, cancellationToken);

                // if the response doesn't send a 401 status code
                if (response.StatusCode != HttpStatusCode.Unauthorized)
                    return response;

                // no WWW-Authenticate header was returned
                // I make it simple: do nothing and let the client handle this!
                if (response.Headers.WwwAuthenticate == null || !response.Headers.WwwAuthenticate.Any())
                    return response;

                authorizationParameter = GetAuthorizationParameter(
                    authorizationParameter, response);

                AddAuthenticationHeader(
                    request,
                    _username, _password,
                    authorizationParameter);

                return await base.SendAsync(request, cancellationToken);
            }
            else
            {
                // the AuthorizationParameter ist in the cache
                AddAuthenticationHeader(
                    request,
                    _username, _password,
                    authorizationParameter);

                var responseThatShouldBeAuthenticated = await base.SendAsync(request, cancellationToken);

                // If already sending an Authorization header but the period of a valid tickets is exceeded, the server sends a 401 status code and the ticket has to be renewed...
                if (responseThatShouldBeAuthenticated.StatusCode == HttpStatusCode.Unauthorized)
                {
                    var renewedAuthorizationParameter = GetAuthorizationParameter(
                        authorizationParameter, responseThatShouldBeAuthenticated);

                    AddAuthenticationHeader(
                        request,
                        _username, _password,
                        renewedAuthorizationParameter);

                    responseThatShouldBeAuthenticated = await base.SendAsync(request, cancellationToken);
                }

                return responseThatShouldBeAuthenticated;
            }
        }

        private static AuthorizationParameter GetAuthorizationParameter(
            AuthorizationParameter authorizationParameter, HttpResponseMessage message)
        {
            var wwwAuthenticateHeader = message.Headers.WwwAuthenticate.First();

            string realm;
            string domain;
            string nonce;
            string qop;
            string cnonce;
            DateTime cnonceDate;

            ParseDigestAuthHeaderData(wwwAuthenticateHeader.Parameter, out realm, out domain, out nonce, out qop, out cnonce, out cnonceDate);

            // delete the old parameter first, this mostly the case, when the server requires a renewal of the parameter
            AuthorizationParameter oldAuthorizationParameter;
            _authorizationCache.TryRemove(
                domain, out oldAuthorizationParameter);

            authorizationParameter = new AuthorizationParameter
            {
                realm = realm,
                nonce = nonce,
                qop = qop,
                cnonce = cnonce,
                cnonceDate = cnonceDate
            };

            _authorizationCache.TryAdd(
                domain, authorizationParameter);

            return authorizationParameter;
        }

        private static void ParseDigestAuthHeaderData(string wwwAuthenticateHeader,
            out string realm, out string domain, out string nonce, out string qop,
            out string cnonce, out DateTime cnonceDate)
        {
            realm = GrabHeaderAuthorizationParameter("realm", wwwAuthenticateHeader);
            domain = GrabHeaderAuthorizationParameter("domain", wwwAuthenticateHeader);
            nonce = GrabHeaderAuthorizationParameter("nonce", wwwAuthenticateHeader);
            qop = GrabHeaderAuthorizationParameter("qop", wwwAuthenticateHeader);

            cnonce = new Random().Next(123400, 9999999).ToString();
            cnonceDate = DateTime.Now;
        }

        private static void AddAuthenticationHeader(HttpRequestMessage request,
            string username, string password, AuthorizationParameter authorizationParameter)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Digest",
                GetDigestHeader(
                    request.RequestUri.PathAndQuery,
                    username, password,
                    authorizationParameter));
        }

        private static string GrabHeaderAuthorizationParameter(string varName, string header)
        {
            var matchHeader = Regex.Match(
                header,
                string.Format("{0}=\"([^\"]*)\"", varName));
            if (matchHeader.Success)
            {
                return matchHeader.Groups[1].Value;
            }
            throw new InvalidOperationException(string.Format("Header {0} not found", varName));
        }

        private static string GetDigestHeader(string path,
            string username, string password,
            AuthorizationParameter fragments)
        {
            return GetDigestHeader(path,
                username, password,
                fragments.realm, fragments.nonce,
                fragments.qop, fragments.nc,
                fragments.cnonce, fragments.cnonceDate);
        }

        private static string GetDigestHeader(string path,
            string username, string password,
            string realm, string nonce, string qop, int nc,
            string cnonce, DateTime cnonceDate)
        {
            var ha1 = CalculateMd5Hash(
                string.Format(
                    "{0}:{1}:{2}", username, realm, password));
            var ha2 = CalculateMd5Hash(
                string.Format(
                    "{0}:{1}", "GET", path));
            var digestResponse = CalculateMd5Hash(
                string.Format(
                    "{0}:{1}:{2:00000000}:{3}:{4}:{5}",
                    ha1, nonce, nc, cnonce, qop, ha2));

            return string.Format(
                "username=\"{0}\", realm=\"{1}\", nonce=\"{2}\", uri=\"{3}\", " +
                "algorithm=MD5, response=\"{4}\", qop={5}, nc={6:00000000}, cnonce=\"{7}\"",
                username, realm, nonce, path, digestResponse, qop, nc, cnonce);
        }

        private static string CalculateMd5Hash(string input)
        {
            var inputBytes = Encoding.ASCII.GetBytes(input);
            var hash = MD5.Create().ComputeHash(inputBytes);
            var sb = new StringBuilder();
            foreach (var b in hash)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        private static bool TryGetCachedAuthorizationParameterByUri(
            Uri requestUri, out AuthorizationParameter authorizationParameter)
        {
            authorizationParameter = null;
            for (int i = requestUri.Segments.Length - 1; i > 0; i--)
            {
                string path = string.Join(string.Empty, requestUri.Segments.Take(i)).TrimEnd('/');
                if (_authorizationCache.TryGetValue(path, out authorizationParameter))
                    return true;
            }
            return false;
        }

        private class AuthorizationParameter
        {
            private int _nc = 0;

            public string realm { get; set; }
            public string nonce { get; set; }
            public string qop { get; set; }
            public string cnonce { get; set; }
            public DateTime cnonceDate { get; set; }

            public int nc
            {
                get { return Interlocked.Increment(ref _nc); }
            }
        }
    }
}