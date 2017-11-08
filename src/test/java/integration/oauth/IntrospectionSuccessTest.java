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
import net.identio.server.service.oauth.model.OAuthToken;
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
        "logging.config: src/test/resources/oauth-server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class IntrospectionSuccessTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private OAuthRequests requests;

    private MultiValueMap<String, String> payload;
    private HttpHeaders headers;

    @Before
    public void setUp() {

        requests = new OAuthRequests(port, restTemplate, "code", "test4", "test4", true);

        requests.authorizeRequest();

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.getConsentContext();

        requests.consent();

        requests.accessTokenRequest();
    }

    @Test
    public void validateAccessTokenWithoutHint() {

        initPayLoadAndHeaders();

        payload.add("token", requests.accessToken);

        ResponseEntity<OAuthToken> introspectResponseEntity = sendIntrospectRequest();

        OAuthToken token = introspectResponseEntity.getBody();

        assertEquals(HttpStatus.OK, introspectResponseEntity.getStatusCode());
        assertEquals("test4", token.getClientId());
        assertEquals("scope.test.1", token.getScope());
        assertEquals("johndoe", token.getUsername());
        assertEquals("johndoe", token.getSubject());
        assertEquals("https://localhost", token.getIssuer());
        assertEquals(true, token.isActive());
    }

    @Test
    public void validateRefreshTokenWithoutHint() {

        initPayLoadAndHeaders();

        payload.add("token", requests.refreshToken);

        ResponseEntity<OAuthToken> introspectResponseEntity = sendIntrospectRequest();

        OAuthToken token = introspectResponseEntity.getBody();

        assertEquals(HttpStatus.OK, introspectResponseEntity.getStatusCode());
        assertEquals("test4", token.getClientId());
        assertEquals("scope.test.1", token.getScope());
        assertEquals("johndoe", token.getUsername());
        assertEquals("johndoe", token.getSubject());
        assertEquals("https://localhost", token.getIssuer());
        assertEquals(true, token.isActive());
    }

    @Test
    public void validateAccessTokenWithHint() {

        initPayLoadAndHeaders();

        payload.add("token", requests.accessToken);
        payload.add("token_type_hint", "access_token");

        ResponseEntity<OAuthToken> introspectResponseEntity = sendIntrospectRequest();

        OAuthToken token = introspectResponseEntity.getBody();

        assertEquals(HttpStatus.OK, introspectResponseEntity.getStatusCode());
        assertEquals("test4", token.getClientId());
        assertEquals("scope.test.1", token.getScope());
        assertEquals("johndoe", token.getUsername());
        assertEquals("johndoe", token.getSubject());
        assertEquals("https://localhost", token.getIssuer());
        assertEquals(true, token.isActive());
    }

    @Test
    public void validateRefreshTokenWithHint() {

        initPayLoadAndHeaders();

        payload.add("token", requests.refreshToken);
        payload.add("token_type_hint", "refresh_token");

        ResponseEntity<OAuthToken> introspectResponseEntity = sendIntrospectRequest();

        OAuthToken token = introspectResponseEntity.getBody();

        assertEquals(HttpStatus.OK, introspectResponseEntity.getStatusCode());
        assertEquals("test4", token.getClientId());
        assertEquals("scope.test.1", token.getScope());
        assertEquals("johndoe", token.getUsername());
        assertEquals("johndoe", token.getSubject());
        assertEquals("https://localhost", token.getIssuer());
        assertEquals(true, token.isActive());
    }

    private ResponseEntity<OAuthToken> sendIntrospectRequest() {

        return restTemplate.exchange(
                "/oauth/introspect",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                OAuthToken.class);
    }

    private void initPayLoadAndHeaders() {

        // Set up default payload and headers
        payload = new LinkedMultiValueMap<>();

        headers = new HttpHeaders();
        headers.set("Authorization", "Basic cnMxOnJzMQ=="); // rs1:rs1 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    }
}
