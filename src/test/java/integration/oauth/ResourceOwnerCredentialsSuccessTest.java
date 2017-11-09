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
import net.identio.server.service.oauth.model.AccessTokenResponse;
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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.application.name: identio",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/oauth-server-config",
        "identio.work.directory: config/work",
        "logging.config: src/test/resources/oauth-server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class ResourceOwnerCredentialsSuccessTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void successfulCinematic() {

        MultiValueMap<String, String> payload = new LinkedMultiValueMap<>();

        payload.add("grant_type", "password");
        payload.add("username", "johndoe");
        payload.add("password", "password");
        payload.add("scope", "scope.test.1 scope.test.2");

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic dGVzdDI6dGVzdDI="); // test2:test2 in base64
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
        assertNull(accessTokenResponse.getRefreshToken());
        assertEquals(2400, accessTokenResponse.getExpiresIn());
        assertEquals("scope.test.1 scope.test.2", accessTokenResponse.getScope());
    }
}
