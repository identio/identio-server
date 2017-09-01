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

package net.identio.server.tests.integ.oauth;

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
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.interfaces.RSAKey;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
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

    public OAuthRequests(int port, TestRestTemplate restTemplate) {
        this.port = port;
        this.restTemplate = restTemplate;
    }

    public void authorizeRequest(String clientId, String responseType) {

        ResponseEntity<String> initialRequestResponse = restTemplate.exchange(
                "/oauth/authorize?client_id=" + clientId + "&redirect_uri=http://example.com/cb&response_type="
                        + responseType + "&scope=scope.test.1 scope.test.2&state=1234",
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
        headers = new HttpHeaders();
        headers.add(HttpHeaders.COOKIE, sessionCookie);
        headers.add("X-Transaction-ID", transactionId);
    }

    public void getAuthMethods() {

        ResponseEntity<AuthMethodResponse[]> authMethodResponse = restTemplate.exchange(
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

        ResponseEntity<AuthSubmitResponse> authSubmitResponseEntity = restTemplate.exchange(
                "/api/auth/submit/password",
                HttpMethod.POST,
                new HttpEntity<>(authenticationSubmit, headers),
                AuthSubmitResponse.class);

        // Check that the authentication is successful and that we're asked for consent
        AuthSubmitResponse authSubmitResponse = authSubmitResponseEntity.getBody();

        assertEquals(HttpStatus.OK, authSubmitResponseEntity.getStatusCode());
        assertEquals(ApiResponseStatus.CONSENT, authSubmitResponse.getStatus());
    }

    public void getConsentContext() {

        // Get information for consent screen
        ResponseEntity<ConsentContext> consentContextEntity = restTemplate.exchange(
                "/api/authz/consent",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                ConsentContext.class);

        ConsentContext consentContext = consentContextEntity.getBody();

        assertEquals("Test Client", consentContext.getAudience());

        List<AuthorizationScope> requestedScopes = consentContext.getRequestedScopes();
        requestedScopes.sort(Comparator.comparing(AuthorizationScope::getName));

        assertTrue(consentContext.getRequestedScopes().size() == 2);

        assertEquals("scope.test.1", consentContext.getRequestedScopes().get(0).getName());
        assertEquals("Accéder à scope test 1", consentContext.getRequestedScopes().get(0).getDescription().get("fr"));
        assertEquals("Access scope test 1", consentContext.getRequestedScopes().get(0).getDescription().get("en"));
        assertEquals("scope.test.2", consentContext.getRequestedScopes().get(1).getName());
    }

    public void consent(String responseType) {

        // Send the consent
        ConsentRequest consentRequest = new ConsentRequest().setApprovedScopes(Collections.singletonList("scope.test.1"));

        ResponseEntity<ConsentResponse> consentResponseEntity = restTemplate.exchange(
                "/api/authz/consent",
                HttpMethod.POST,
                new HttpEntity<>(consentRequest, headers),
                ConsentResponse.class);

        ConsentResponse consentResponse = consentResponseEntity.getBody();
        this.responseUrl = consentResponse.getResponseData().getUrl();

        if ("token".equals(responseType)) {
            assertTrue(this.responseUrl
                    .matches("^http://example.com/cb#expires_in=2400&token_type=Bearer&access_token=.*&state=1234"));
        }
        if ("code".equals(responseType)) {
            assertTrue(this.responseUrl
                    .matches("^http://example.com/cb#expires_in=2400&token_type=Bearer&code=.*&state=1234"));
        }
    }

    public void validateResponse() {
        // Parse and validate JWT
        Algorithm algorithm = null;
        try {
            algorithm = Algorithm.RSA256(getPublicSigningKey());
        } catch (Exception e) {
            fail();
        }

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("https://localhost")
                .withSubject("johndoe")
                .withAudience("Test Client")
                .withClaim("scope", "scope.test.1")
                .build();

        Pattern pattern = Pattern.compile("^http://example.com/cb#expires_in=2400&token_type=Bearer&access_token=(.*)&state=1234");
        Matcher matcher = pattern.matcher(this.responseUrl);

        if (matcher.find()) {
            verifier.verify(matcher.group(1));
        } else {
            fail();
        }
    }

    private String getUrlWithPort(String url) {

        return "http://localhost:" + port + url;
    }

    private String getSessionCookie(ResponseEntity<?> response) {

        return response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
    }

    private String getTransactionId(String url) {

        return url.substring(getUrlWithPort(AUTHENTICATION_URL).length());
    }

    private RSAKey getPublicSigningKey() throws Exception {

        FileInputStream fis = new FileInputStream(
                "src/test/resources/oauth-server-config/default-sign-certificate.p12");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(fis, "password".toCharArray());

        Enumeration<String> aliases = ks.aliases();

        String alias = aliases.nextElement();

        return (RSAKey) (ks.getCertificate(alias)).getPublicKey();

    }
}
