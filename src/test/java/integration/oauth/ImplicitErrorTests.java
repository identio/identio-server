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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.application.name: identio",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/oauth-server-config",
        "identio.work.directory: config/work",
        "logging.config: src/test/resources/oauth-server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class ImplicitErrorTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private static final String AUTHORIZE_URL = "/oauth/authorize";
    private static final String AUTHENTICATION_URL = "/#!/auth/";
    private static final String UNKNOWN_CLIENT_ERROR_URL = "/#!/error/unknown.client";
    private static final String UNSUPPORTED_RESPONSE_TYPE_ERROR_URL = "http://example.com/cb#error=unsupported_response_type&state=1234";
    private static final String UNAUTHORIZED_CLIENT_ERROR_URL = "http://example.com/cb#error=unauthorized_client&state=1234";
    private static final String UNKNOWN_REDIRECT_URI_ERROR_URL = "/#!/error/unknown.redirect.uri";
    private static final String INVALID_SCOPE_ERROR_URI = "http://example.com/cb#error=invalid_scope&state=1234";

    @Test
    public void oAuthAuthorizeRequestWithoutParameters() {

        ResponseEntity<String> response = restTemplate.exchange(
                AUTHORIZE_URL,
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort(UNKNOWN_CLIENT_ERROR_URL), response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutClientId() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?response_type=token&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort(UNKNOWN_CLIENT_ERROR_URL), response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithInvalidClientId() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=invalid&response_type=token&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort(UNKNOWN_CLIENT_ERROR_URL), response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutResponseType() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=test&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(UNSUPPORTED_RESPONSE_TYPE_ERROR_URL, response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithInvalidResponseType() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=test&response_type=invalid&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(UNSUPPORTED_RESPONSE_TYPE_ERROR_URL, response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithUnauthorizedResponseType() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=test&response_type=code&redirect_uri=http://example.com/cb&scope=scope.test.1&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(UNAUTHORIZED_CLIENT_ERROR_URL, response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutRedirectUri() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=test&response_type=token&scope=scope.test.1&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertTrue(response.getHeaders().getFirst(HttpHeaders.LOCATION).startsWith(getUrlWithPort(AUTHENTICATION_URL)));
    }

    @Test
    public void oAuthAuthorizeRequestWithUnknownUri() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=test&redirect_uri=http://evil.com/cb&response_type=token&scope=scope.test.1&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(getUrlWithPort(UNKNOWN_REDIRECT_URI_ERROR_URL), response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithoutScope() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=test&http://example.com/cb&response_type=token&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(INVALID_SCOPE_ERROR_URI, response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    @Test
    public void oAuthAuthorizeRequestWithInvalidScope() {

        ResponseEntity<String> response = restTemplate.exchange(
                "/oauth/authorize?client_id=test&http://example.com/cb&response_type=token&scope=invalid&state=1234",
                HttpMethod.GET,
                new HttpEntity<String>(null, new HttpHeaders()),
                String.class);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(INVALID_SCOPE_ERROR_URI, response.getHeaders().getFirst(HttpHeaders.LOCATION));
    }

    private String getUrlWithPort(String url) {

        return "http://localhost:" + port + url;

    }
}
