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
import net.identio.server.mvc.oauth.model.OAuthApiErrorResponse;
import net.identio.server.service.oauth.model.OAuthErrors;
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
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.application.name: identio",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/oauth-server-config",
        "identio.work.directory: config/work",
        "logging.config: src/test/resources/oauth-server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class IntrospectionErrorTests {

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
    public void missingToken() {

        initPayLoadAndHeaders();

        payload.add("token_type_hint", "access_token");

        ResponseEntity<OAuthApiErrorResponse> introspectResponseEntity = sendIntrospectRequest();

        assertEquals(HttpStatus.BAD_REQUEST, introspectResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_REQUEST, introspectResponseEntity.getBody().getError());
    }

    @Test
    public void invalidToken() {

        initPayLoadAndHeaders();

        payload.add("token", "invalid");

        ResponseEntity<OAuthToken> introspectResponseEntity = sendValidIntrospectRequest();

        OAuthToken token = introspectResponseEntity.getBody();

        assertEquals(HttpStatus.OK, introspectResponseEntity.getStatusCode());
        assertEquals(false, token.isActive());
    }

    @Test
    public void invalidTokenTypeHint() {

        initPayLoadAndHeaders();

        payload.add("token_type_hint", "invalid");

        ResponseEntity<OAuthApiErrorResponse> introspectResponseEntity = sendIntrospectRequest();

        assertEquals(HttpStatus.BAD_REQUEST, introspectResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_REQUEST, introspectResponseEntity.getBody().getError());

    }

    @Test
    public void invertTokenTypeHint() {

        initPayLoadAndHeaders();

        payload.add("token", requests.accessToken);
        payload.add("token_type_hint", "refresh_token");

        ResponseEntity<OAuthToken> introspectResponseEntity = sendValidIntrospectRequest();

        OAuthToken token = introspectResponseEntity.getBody();

        assertEquals(HttpStatus.OK, introspectResponseEntity.getStatusCode());
        assertEquals(false, token.isActive());
    }

    @Test
    public void invalidAuthentication() {

        initPayLoadAndHeaders();

        payload.add("token", requests.accessToken);
        payload.add("token_type_hint", "access_token");

        headers.remove("Authorization");
        headers.add("Authorization", "Basic cnMxOnJzMg=="); // rs1:rs2 in Base 64

        ResponseEntity<OAuthApiErrorResponse> introspectResponseEntity = sendIntrospectRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, introspectResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, introspectResponseEntity.getBody().getError());
    }

    @Test
    public void missingAuthentication() {

        initPayLoadAndHeaders();

        payload.add("token", requests.accessToken);
        payload.add("token_type_hint", "access_token");

        headers.remove("Authorization");

        ResponseEntity<OAuthApiErrorResponse> introspectResponseEntity = sendIntrospectRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, introspectResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, introspectResponseEntity.getBody().getError());
    }

    @Test
    public void useClientAuthenticationInsteadOfResourceServer() {

        initPayLoadAndHeaders();

        payload.add("token", requests.accessToken);
        payload.add("token_type_hint", "access_token");

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdDM6dGVzdDM="); // test3:test3 in Base 64

        ResponseEntity<OAuthApiErrorResponse> introspectResponseEntity = sendIntrospectRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, introspectResponseEntity.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, introspectResponseEntity.getBody().getError());

    }

    private ResponseEntity<OAuthApiErrorResponse> sendIntrospectRequest() {

        return restTemplate.exchange(
                "/oauth/introspect",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                OAuthApiErrorResponse.class);
    }

    private ResponseEntity<OAuthToken> sendValidIntrospectRequest() {

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
