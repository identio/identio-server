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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.cloud.config.name: identio-config",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/oauth-server-config",
        "logging.config: src/test/resources/oauth-server-config/logback.xml"})
@ActiveProfiles(profiles = {"native"})
public class AuthorizationCodePkceSuccessTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void successfulCinematic() {

        OAuthRequests requests = new OAuthRequests(port, restTemplate, "code", "test2", true);

        requests.authorizeRequest();

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.getConsentContext();

        requests.consent();

        requests.accessTokenRequest();

        requests.validateResponse();

        requests.refreshTokenRequest();
    }
}
