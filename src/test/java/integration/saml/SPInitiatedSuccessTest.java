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

package integration.saml;

import net.identio.saml.exceptions.*;
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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.application.name: identio",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/server-config",
        "identio.work.directory: config/work",
        "logging.config: src/test/resources/server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class SPInitiatedSuccessTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    public void successfulUnsignedHttpRedirectCinematic() throws TechnicalException, IOException, InvalidAuthentResponseException, InvalidAssertionException, InvalidSignatureException, UntrustedSignerException, NoSuchAlgorithmException, UnsignedSAMLObjectException {

        SamlRequests requests = new SamlRequests(port, restTemplate);

        requests.httpRedirectSamlRequest(false);

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.validateResponse();
    }

    @Test
    public void successfulUnsignedHttpPostCinematic() throws TechnicalException, IOException, InvalidAuthentResponseException, InvalidAssertionException, InvalidSignatureException, UntrustedSignerException, NoSuchAlgorithmException, UnsignedSAMLObjectException {

        SamlRequests requests = new SamlRequests(port, restTemplate);

        requests.httpPostSamlRequest(false);

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.validateResponse();
    }

    @Test
    public void successfulSignedHttpRedirectCinematic() throws TechnicalException, IOException, InvalidAuthentResponseException, InvalidAssertionException, InvalidSignatureException, UntrustedSignerException, NoSuchAlgorithmException, UnsignedSAMLObjectException {

        SamlRequests requests = new SamlRequests(port, restTemplate);

        requests.httpRedirectSamlRequest(true);

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.validateResponse();
    }

    @Test
    public void successfulSignedHttpPostCinematic() throws TechnicalException, IOException, InvalidAuthentResponseException, InvalidAssertionException, InvalidSignatureException, UntrustedSignerException, NoSuchAlgorithmException, UnsignedSAMLObjectException {

        SamlRequests requests = new SamlRequests(port, restTemplate);

        requests.httpPostSamlRequest(true);

        requests.getAuthMethods();

        requests.authenticateLocal();

        requests.validateResponse();
    }
}
