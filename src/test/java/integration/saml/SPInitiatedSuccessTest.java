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

import integration.oauth.OAuthRequests;
import net.identio.saml.*;
import net.identio.saml.exceptions.TechnicalException;
import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.mvc.oauth.model.OAuthApiErrorResponse;
import net.identio.server.service.authentication.model.Authentication;
import net.identio.server.service.oauth.model.OAuthErrors;
import net.identio.server.service.oauth.model.OAuthToken;
import net.identio.server.utils.DecodeUtils;
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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.application.name: identio",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/server-config",
        "identio.work.directory: config/work",
        "logging.config: src/test/resources/server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class SPInitiatedSuccessTest {

    private static final String AUTHENTICATION_URL = "/#!/auth/";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private MultiValueMap<String, String> payload;
    private HttpHeaders headers;

    @Test
    public void successfulCinematic() throws TechnicalException, IOException {

        AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination("https://localhost/SAML2/SSO/Redirect")
                .setForceAuthent(false).setIsPassive(false).setIssuer("http://client.ident.io/SAML2")
                .build();

        String url = "/SAML2/SSO/Redirect?SAMLRequest=" + DecodeUtils.encode(ar.toString().getBytes(), true);

        ResponseEntity<String> request = this.restTemplate.exchange(
                url,
                HttpMethod.GET,
                null,
                String.class);

        String redirectUrl = request.getHeaders().getFirst(HttpHeaders.LOCATION);

        assertEquals(HttpStatus.FOUND, request.getStatusCode());
        assertTrue(redirectUrl.startsWith(getUrlWithPort(AUTHENTICATION_URL)));

    }

    private String getUrlWithPort(String url) {

        return "http://localhost:" + this.port + url;
    }
}
