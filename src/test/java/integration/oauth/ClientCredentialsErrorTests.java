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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.junit.Assert.assertEquals;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"identio.config: src/test/resources/oauth-server-config/identio-config.yml",
        "logging.config: src/test/resources/oauth-server-config/logback.xml"})
public class ClientCredentialsErrorTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private MultiValueMap<String, String> payload;
    private HttpHeaders headers;

    @Test
    public void wrongPassword() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdDI6dGVzdA==");

        ResponseEntity<AccessTokenErrorResponse> response = sendClientCredentialsRequest();

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        assertEquals(OAuthErrors.INVALID_CLIENT, response.getBody().getError());
    }

    @Test
    public void unauthorizedClient() {

        initPayLoadAndHeaders();

        headers.remove("Authorization");
        headers.add("Authorization", "Basic dGVzdDM6dGVzdDM=");

        ResponseEntity<AccessTokenErrorResponse> response = sendClientCredentialsRequest();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuthErrors.UNAUTHORIZED_CLIENT, response.getBody().getError());
    }

    @Test
    public void unauthorizedScope() {

        initPayLoadAndHeaders();

        payload.add("scope", "scope.test.3");

        ResponseEntity<AccessTokenErrorResponse> response = sendClientCredentialsRequest();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuthErrors.INVALID_SCOPE, response.getBody().getError());
    }

    private ResponseEntity<AccessTokenErrorResponse> sendClientCredentialsRequest() {

        return restTemplate.exchange(
                "/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                AccessTokenErrorResponse.class);
    }

    private void initPayLoadAndHeaders() {

        // Set up default payload and headers
        payload = new LinkedMultiValueMap<>();
        payload.add("grant_type", "client_credentials");

        headers = new HttpHeaders();
        headers.set("Authorization", "Basic dGVzdDI6dGVzdDI="); // test2:test2 in base64
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    }

}
