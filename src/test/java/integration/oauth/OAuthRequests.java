/*
 * This file is part of Ident.io.
 *
 * Ident.io - A flexible authentication server
 * Copyright (c) 2017 Loeiz TANGUY
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package integration.oauth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import net.identio.server.model.AuthorizationScope;
import net.identio.server.mvc.common.model.ApiResponseStatus;
import net.identio.server.mvc.common.model.AuthMethodResponse;
import net.identio.server.mvc.common.model.AuthSubmitRequest;
import net.identio.server.mvc.common.model.AuthSubmitResponse;
import net.identio.server.mvc.oauth.model.ConsentContext;
import net.identio.server.mvc.oauth.model.ConsentRequest;
import net.identio.server.mvc.oauth.model.ConsentResponse;
import net.identio.server.service.oauth.model.AccessTokenResponse;
import net.identio.server.service.oauth.model.OAuthToken;
import org.junit.Assert;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.*;
import static org.junit.Assert.fail;

public class OAuthRequests {

    private static final String AUTHENTICATION_URL = "/#!/auth/";

    private int port;
    private TestRestTemplate restTemplate;

    private HttpHeaders headers;
    private String responseUrl;
    private String responseType;
    private String clientId;
    private boolean enablePkce;
    private String codeVerifier;
    private String authorizationHeader;

    public String authorizationCode;
    public String accessToken;
    public String refreshToken;

    public OAuthRequests(int port, TestRestTemplate restTemplate, String responseType, String clientId, String clientSecret,
                         boolean enablePkce) {
        this.port = port;
        this.restTemplate = restTemplate;
        this.responseType = responseType;
        this.clientId = clientId;
        this.enablePkce = enablePkce;
        this.authorizationHeader = "Basic " +
                Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes());
    }

    public void authorizeRequest() {

        String url = "/oauth/authorize?client_id=" + this.clientId + "&redirect_uri=http://example.com/cb&response_type="
                + this.responseType + "&scope=scope.test.1 scope.test.2&state=1234";

        if (enablePkce) {

            try {

                this.codeVerifier = UUID.randomUUID().toString();

                String challenge = Base64.getEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(this.codeVerifier.getBytes(StandardCharsets.US_ASCII)));

                url += "&code_challenge=" + challenge;

            } catch (NoSuchAlgorithmException e) {
                Assert.fail();
            }
        }

        ResponseEntity<String> initialRequestResponse = this.restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(null, new HttpHeaders()),
                String.class);

        // Redirect to the login page
        String redirectUrl = initialRequestResponse.getHeaders().getFirst(HttpHeaders.LOCATION);

        assertEquals(HttpStatus.FOUND, initialRequestResponse.getStatusCode());
        assertTrue(redirectUrl.startsWith(getUrlWithPort(AUTHENTICATION_URL)));

        String sessionCookie = getSessionCookie(initialRequestResponse);
        String transactionId = getTransactionId(redirectUrl);

        assertTrue(sessionCookie.startsWith("identioSession="));
        assertNotNull(transactionId);

        // Request authentication methods
        this.headers = new HttpHeaders();
        this.headers.add(HttpHeaders.COOKIE, sessionCookie);
        this.headers.add("X-Transaction-ID", transactionId);
    }

    public void getAuthMethods() {

        ResponseEntity<AuthMethodResponse[]> authMethodResponse = this.restTemplate.exchange(
                "/api/auth/methods",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                AuthMethodResponse[].class);

        assertEquals(HttpStatus.OK, authMethodResponse.getStatusCode());
        assertEquals(1, authMethodResponse.getBody().length);
        assertEquals("Local", authMethodResponse.getBody()[0].getName());
        assertEquals("local", authMethodResponse.getBody()[0].getType());

    }

    public void authenticateLocal() {

        AuthSubmitRequest authenticationSubmit = new AuthSubmitRequest().setLogin("johndoe").setPassword("password")
                .setMethod("Local");

        ResponseEntity<AuthSubmitResponse> authSubmitResponseEntity = this.restTemplate.exchange(
                "/api/auth/submit/password",
                HttpMethod.POST,
                new HttpEntity<>(authenticationSubmit, this.headers),
                AuthSubmitResponse.class);

        // Check that the authentication is successful and that we're asked for consent
        AuthSubmitResponse authSubmitResponse = authSubmitResponseEntity.getBody();

        assertEquals(HttpStatus.OK, authSubmitResponseEntity.getStatusCode());
        assertEquals(ApiResponseStatus.CONSENT, authSubmitResponse.getStatus());
    }

    public void getConsentContext() {

        // Get information for consent screen
        ResponseEntity<ConsentContext> consentContextEntity = this.restTemplate.exchange(
                "/api/authz/consent",
                HttpMethod.GET,
                new HttpEntity<>(null, this.headers),
                ConsentContext.class);

        ConsentContext consentContext = consentContextEntity.getBody();

        assertEquals(this.clientId, consentContext.getAudience());

        List<AuthorizationScope> requestedScopes = consentContext.getRequestedScopes();
        requestedScopes.sort(Comparator.comparing(AuthorizationScope::getName));

        assertTrue(consentContext.getRequestedScopes().size() == 2);

        assertEquals("scope.test.1", consentContext.getRequestedScopes().get(0).getName());
        assertEquals("Accéder à scope test 1", consentContext.getRequestedScopes().get(0).getDescription().get("fr"));
        assertEquals("Access scope test 1", consentContext.getRequestedScopes().get(0).getDescription().get("en"));
        assertEquals("scope.test.2", consentContext.getRequestedScopes().get(1).getName());
    }

    public void consent() {

        // Send the consent
        ConsentRequest consentRequest = new ConsentRequest().setApprovedScopes(Collections.singletonList("scope.test.1"));

        ResponseEntity<ConsentResponse> consentResponseEntity = this.restTemplate.exchange(
                "/api/authz/consent",
                HttpMethod.POST,
                new HttpEntity<>(consentRequest, this.headers),
                ConsentResponse.class);

        ConsentResponse consentResponse = consentResponseEntity.getBody();
        this.responseUrl = consentResponse.getResponseData().getUrl();

        if ("token".equals(this.responseType)) {
            assertTrue(this.responseUrl
                    .matches("^http://example.com/cb#expires_in=2400&token_type=Bearer&access_token=.*&state=1234"));

            Pattern pattern = Pattern.compile("^http://example.com/cb#expires_in=2400&token_type=Bearer&access_token=(.*)&state=1234");
            Matcher matcher = pattern.matcher(this.responseUrl);

            if (matcher.find()) {
                this.accessToken = matcher.group(1);
            } else {
                fail();
            }

        }
        if ("code".equals(this.responseType)) {
            assertTrue(this.responseUrl
                    .matches("^http://example.com/cb\\?code=.*&state=1234"));

            Pattern pattern = Pattern.compile("^http://example.com/cb\\?code=(.*)&state=1234");
            Matcher matcher = pattern.matcher(this.responseUrl);

            if (matcher.find()) {
                this.authorizationCode = matcher.group(1);
            } else {
                fail();
            }
        }
    }

    public void validateResponse() {

        // Parse and validate JWT
        Algorithm algorithm = null;
        try {
            algorithm = Algorithm.RSA256(getPublicSigningKey(), null);
        } catch (Exception e) {
            fail();
        }

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("https://localhost")
                .withSubject("johndoe")
                .withClaim("scope", "scope.test.1")
                .withClaim("client_id", this.clientId)
                .build();

        verifier.verify(this.accessToken);
    }

    public void accessTokenRequest() {

        MultiValueMap<String, String> payload = new LinkedMultiValueMap<>();

        payload.add("grant_type", "authorization_code");
        payload.add("code", this.authorizationCode);
        payload.add("redirect_uri", "http://example.com/cb");

        if (this.enablePkce) {
            payload.add("code_verifier", this.codeVerifier);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", this.authorizationHeader); // test2:test2 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ResponseEntity<AccessTokenResponse> accessTokenResponseEntity = this.restTemplate.exchange(
                "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                AccessTokenResponse.class);

        AccessTokenResponse accessTokenResponse = accessTokenResponseEntity.getBody();

        this.accessToken = accessTokenResponse.getAccessToken();
        this.refreshToken = accessTokenResponse.getRefreshToken();

        assertEquals(HttpStatus.OK, accessTokenResponseEntity.getStatusCode());
        assertNotNull(this.accessToken);
        assertNotNull(this.refreshToken);
        assertEquals(2400, accessTokenResponse.getExpiresIn());
        assertEquals("scope.test.1", accessTokenResponse.getScope());
    }

    public void refreshTokenRequest() {

        MultiValueMap<String, String> payload = new LinkedMultiValueMap<>();

        payload.add("grant_type", "refresh_token");
        payload.add("refresh_token", this.refreshToken);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", this.authorizationHeader); // test2:test2 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ResponseEntity<AccessTokenResponse> accessTokenResponseEntity = this.restTemplate.exchange(
                "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                AccessTokenResponse.class);

        AccessTokenResponse accessTokenResponse = accessTokenResponseEntity.getBody();

        String accessToken = accessTokenResponse.getAccessToken();

        assertEquals(HttpStatus.OK, accessTokenResponseEntity.getStatusCode());
        assertNotNull(accessToken);
        assertNotEquals(this.accessToken, accessToken);
        assertNull(accessTokenResponse.getRefreshToken());
        assertEquals(2400, accessTokenResponse.getExpiresIn());
        assertEquals("scope.test.1", accessTokenResponse.getScope());

        this.accessToken = accessToken;
    }

    public void introspectionRequest() {

        MultiValueMap<String, String> payload = new LinkedMultiValueMap<>();

        payload.add("token", this.accessToken);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic cnMxOnJzMQ=="); // rs1:rs1 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ResponseEntity<OAuthToken> introspectionResponseEntity = this.restTemplate.exchange(
                "/oauth/introspect",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                OAuthToken.class);

        OAuthToken introspectionResponse = introspectionResponseEntity.getBody();

        assertEquals(HttpStatus.OK, introspectionResponseEntity.getStatusCode());
        assertNotNull(introspectionResponse);

        assertEquals("test", introspectionResponse.getClientId());
        assertEquals("scope.test.1", introspectionResponse.getScope());
        assertEquals("johndoe", introspectionResponse.getUsername());
        assertEquals("johndoe", introspectionResponse.getSubject());
        assertEquals("https://localhost", introspectionResponse.getIssuer());
        assertEquals(true, introspectionResponse.isActive());
    }

    private String getUrlWithPort(String url) {

        return "http://localhost:" + this.port + url;
    }

    private String getSessionCookie(ResponseEntity<?> response) {

        return response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
    }

    private String getTransactionId(String url) {

        return url.substring(getUrlWithPort(AUTHENTICATION_URL).length());
    }

    private RSAPublicKey getPublicSigningKey() throws Exception {

        FileInputStream fis = new FileInputStream(
                "src/test/resources/oauth-server-config/default-sign-certificate.p12");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(fis, "password".toCharArray());

        Enumeration<String> aliases = ks.aliases();

        String alias = aliases.nextElement();

        return (RSAPublicKey) (ks.getCertificate(alias)).getPublicKey();

    }
}
