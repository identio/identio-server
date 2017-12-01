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
import net.identio.saml.exceptions.InvalidAuthentResponseException;
import net.identio.saml.exceptions.TechnicalException;
import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.mvc.oauth.model.OAuthApiErrorResponse;
import net.identio.server.service.oauth.model.OAuthErrors;
import net.identio.server.service.saml.model.SamlErrors;
import net.identio.server.utils.DecodeUtils;
import org.junit.Assert;
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
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = IdentioServerApplication.class)
@TestPropertySource(properties = {"spring.cloud.config.server.bootstrap: true", "spring.application.name: identio",
        "spring.cloud.config.server.native.searchLocations: file:src/test/resources/server-config",
        "identio.work.directory: config/work",
        "logging.config: src/test/resources/server-config/logback.xml", "spring.cloud.vault.enabled: false"})
@ActiveProfiles(profiles = {"native"})
public class HttpRedirectAuthentRequestErrorTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private MultiValueMap<String, String> payload;

    private static final String INVALID_REQUEST_ERROR_URL = "/#!/error/invalid.request";

    @Test
    public void missingSamlRequest() throws TechnicalException {

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getUrlWithPort("/SAML2/SSO/Redirect"));

        ResponseEntity<String> request = sendAuthentRequest(builder);

        String redirectUrl = request.getHeaders().getFirst(HttpHeaders.LOCATION);

        assertEquals(HttpStatus.FOUND, request.getStatusCode());
        assertEquals(getUrlWithPort(INVALID_REQUEST_ERROR_URL), redirectUrl);
    }

    @Test
    public void invalidSamlRequest() {

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getUrlWithPort("/SAML2/SSO/Redirect"));
        builder.queryParam("SAMLRequest", "invalid");
        builder.queryParam("RelayState", UUID.randomUUID().toString());

        ResponseEntity<String> request = sendAuthentRequest(builder);

        String redirectUrl = request.getHeaders().getFirst(HttpHeaders.LOCATION);

        assertEquals(HttpStatus.FOUND, request.getStatusCode());
        assertEquals(getUrlWithPort(INVALID_REQUEST_ERROR_URL), redirectUrl);
    }

    @Test
    public void missingSigAlg() throws TechnicalException, InvalidAuthentResponseException {
/*
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getUrlWithPort("/SAML2/SSO/Redirect"));

        AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination("https://localhost/SAML2/SSO/Redirect")
                .setForceAuthent(false).setIsPassive(false).setIssuer("http://client.ident.io/SAML2")
                .build();

        builder.queryParam("SAMLRequest", DecodeUtils.encode(ar.toString().getBytes(), true).get());
        builder.queryParam("RelayState", UUID.randomUUID().toString());

        Signer signer = new Signer("src/test/resources/saml-sp-config/certificate.p12",
                "password", false, SamlConstants.SIGNATURE_ALG_RSA_SHA256);

        String signedInfo = builder.build().encode().toUri().getRawQuery();

        byte[] signature = signer.signExternal(signedInfo);
        builder.queryParam("Signature", DecodeUtils.encode(signature, false).get());

        ResponseEntity<String> request = sendAuthentRequest(builder);

        assertEquals(HttpStatus.OK, request.getStatusCode());

        assertTrue(request.getBody().contains("<title>Ident.io SAML Responder</title></head>"));

        Pattern pattern = Pattern.compile("<input type=\"hidden\" name=\"SAMLResponse\" value=\"(.*)\">");
        Matcher matcher = pattern.matcher(request.getBody());

        if (matcher.find()) {

            String response = matcher.group(1);

            String decodedResponse = new String(DecodeUtils.decode(response, false).get());

            AuthentResponse authentResponse = AuthentResponseBuilder.getInstance().build(decodedResponse);


        } else Assert.fail("No SAML Response found");

*/
    }

    @Test
    public void invalidSigAlg() throws TechnicalException {
/*
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getUrlWithPort("/SAML2/SSO/Redirect"));

        AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination("https://localhost/SAML2/SSO/Redirect")
                .setForceAuthent(false).setIsPassive(false).setIssuer("http://client.ident.io/SAML2")
                .build();

        builder.queryParam("SAMLRequest", DecodeUtils.encode(ar.toString().getBytes(), true).get());
        builder.queryParam("RelayState", UUID.randomUUID().toString());
        builder.queryParam("SigAlg", "invalid");

        Signer signer = new Signer("src/test/resources/saml-sp-config/certificate.p12",
                "password", false, SamlConstants.SIGNATURE_ALG_RSA_SHA256);

        String signedInfo = builder.build().encode().toUri().getRawQuery();

        byte[] signature = signer.signExternal(signedInfo);
        builder.queryParam("Signature", DecodeUtils.encode(signature, false).get());

        ResponseEntity<String> request = sendAuthentRequest(builder);

        String redirectUrl = request.getHeaders().getFirst(HttpHeaders.LOCATION);

        assertEquals(HttpStatus.FOUND, request.getStatusCode());
        assertEquals(getUrlWithPort(INVALID_REQUEST_ERROR_URL), redirectUrl);
*/
    }

    @Test
    public void missingSignature() {


    }

    @Test
    public void invalidSignature() {


    }

    @Test
    public void untrustedRequestSigner() {


    }

    private ResponseEntity<String> sendAuthentRequest(UriComponentsBuilder builder) {
        return this.restTemplate.exchange(
                builder.build().encode().toUri(),
                HttpMethod.GET,
                null,
                String.class);
    }

    private String getUrlWithPort(String url) {

        return "http://localhost:" + this.port + url;
    }

}
