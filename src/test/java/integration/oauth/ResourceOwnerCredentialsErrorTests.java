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

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.application.name: identio",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/server-config",
        "identio.work.directory: config/work",
        "logging.config: src/test/resources/server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class ResourceOwnerCredentialsErrorTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private MultiValueMap<String, String> payload;
    private HttpHeaders headers;

    @Test
    public void missingUsername() {

        initPayLoadAndHeaders();

        payload.remove("username");

        ResponseEntity<OAuthApiErrorResponse> response = sendResourceOwnerCredentialsRequest();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuthErrors.INVALID_REQUEST, response.getBody().getError());
    }

    @Test
    public void missingPassword() {

        initPayLoadAndHeaders();

        payload.remove("password");

        ResponseEntity<OAuthApiErrorResponse> response = sendResourceOwnerCredentialsRequest();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuthErrors.INVALID_REQUEST, response.getBody().getError());
    }

    @Test
    public void wrongPassword() {

        initPayLoadAndHeaders();

        payload.remove("password");
        payload.add("password", "wrong");

        ResponseEntity<OAuthApiErrorResponse> response = sendResourceOwnerCredentialsRequest();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuthErrors.INVALID_GRANT, response.getBody().getError());
    }

    @Test
    public void unauthorizedClient() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdDM6dGVzdDM="); // test3:test3

        ResponseEntity<OAuthApiErrorResponse> response = sendResourceOwnerCredentialsRequest();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuthErrors.UNAUTHORIZED_CLIENT, response.getBody().getError());
    }

    @Test
    public void wrongClientAuthentication() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdD\\6dGVzdDM="); // test2:test3

        ResponseEntity<OAuthApiErrorResponse> response = sendResourceOwnerCredentialsRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, response.getBody().getError());
    }

    @Test
    public void unauthorizedScope() {

        initPayLoadAndHeaders();

        payload.add("scope", "scope.test.3");

        ResponseEntity<OAuthApiErrorResponse> response = sendResourceOwnerCredentialsRequest();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuthErrors.INVALID_SCOPE, response.getBody().getError());

    }


    private ResponseEntity<OAuthApiErrorResponse> sendResourceOwnerCredentialsRequest() {

        return restTemplate.exchange(
                "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                OAuthApiErrorResponse.class);
    }

    private void initPayLoadAndHeaders() {

        // Set up default payload and headers
        payload = new LinkedMultiValueMap<>();
        payload.add("grant_type", "password");
        payload.add("username", "johndoe");
        payload.add("password", "password");

        headers = new HttpHeaders();
        headers.set("Authorization", "Basic dGVzdDI6dGVzdDI="); // test2:test2 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    }

}
