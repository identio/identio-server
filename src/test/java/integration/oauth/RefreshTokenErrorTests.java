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

import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.mvc.oauth.model.AccessTokenErrorResponse;
import net.identio.server.service.oauth.model.OAuthErrors;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.cloud.config.name: identio-config",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/oauth-server-config",
        "logging.config: src/test/resources/oauth-server-config/logback.xml"})
@ActiveProfiles(profiles = {"native"})
public class RefreshTokenErrorTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private OAuthRequests requests;

    private MultiValueMap<String, String> payload;
    private HttpHeaders headers;

    @Before
    public void setUp() {

        requests = new OAuthRequests(port, restTemplate, "code", "test2");

        requests.authorizeRequest();

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.getConsentContext();

        requests.consent();

        requests.accessTokenRequest();

    }

    @Test
    public void requestWithoutRefreshToken() {

        initPayLoadAndHeaders();

        payload.remove("refresh_token");

        ResponseEntity<AccessTokenErrorResponse> refreshTokenResponse = sendRefreshTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, refreshTokenResponse.getStatusCode());
        assertEquals(OAuthErrors.INVALID_REQUEST, refreshTokenResponse.getBody().getError());
    }

    @Test
    public void invalidRefreshToken() {

        initPayLoadAndHeaders();

        payload.remove("refresh_token");
        payload.add("refresh_token", "123456");

        ResponseEntity<AccessTokenErrorResponse> refreshTokenResponse = sendRefreshTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, refreshTokenResponse.getStatusCode());
        assertEquals(OAuthErrors.INVALID_GRANT, refreshTokenResponse.getBody().getError());
    }

    @Test
    public void invalidScope() {

        initPayLoadAndHeaders();

        payload.add("scope", "scope.invalid");

        ResponseEntity<AccessTokenErrorResponse> refreshTokenResponse = sendRefreshTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, refreshTokenResponse.getStatusCode());
        assertEquals(OAuthErrors.INVALID_SCOPE, refreshTokenResponse.getBody().getError());
    }

    @Test
    public void notGrantedScope() {

        initPayLoadAndHeaders();

        payload.add("scope", "scope.test.2");

        ResponseEntity<AccessTokenErrorResponse> refreshTokenResponse = sendRefreshTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, refreshTokenResponse.getStatusCode());
        assertEquals(OAuthErrors.INVALID_SCOPE, refreshTokenResponse.getBody().getError());
    }

    @Test
    public void useAnotherClientId() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdDQ6dGVzdDQ="); // test4:test4

        ResponseEntity<AccessTokenErrorResponse> refreshTokenResponse = sendRefreshTokenRequest();

        assertEquals(HttpStatus.BAD_REQUEST, refreshTokenResponse.getStatusCode());
        assertEquals(OAuthErrors.INVALID_GRANT, refreshTokenResponse.getBody().getError());
    }

    private ResponseEntity<AccessTokenErrorResponse> sendRefreshTokenRequest() {

        return restTemplate.exchange(
                "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                AccessTokenErrorResponse.class);
    }

    private void initPayLoadAndHeaders() {

        // Set up default payload and headers
        payload = new LinkedMultiValueMap<>();
        payload.add("grant_type", "refresh_token");
        payload.add("refresh_token", requests.refreshToken);

        headers = new HttpHeaders();
        headers.set("Authorization", "Basic dGVzdDI6dGVzdDI="); // test3:test3 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    }

}
