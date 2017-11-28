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

import net.identio.saml.*;
import net.identio.saml.exceptions.*;
import net.identio.server.mvc.common.model.ApiResponseStatus;
import net.identio.server.mvc.common.model.AuthMethodResponse;
import net.identio.server.mvc.common.model.AuthSubmitRequest;
import net.identio.server.mvc.common.model.AuthSubmitResponse;
import net.identio.server.utils.DecodeUtils;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

import static org.junit.Assert.*;

public class SamlRequests {

    private static final String AUTHENTICATION_URL = "/#!/auth/";

    private int port;
    private TestRestTemplate restTemplate;

    private HttpHeaders headers;

    private String requestId;
    private AuthentResponse ar;
    private String responseUrl;
    private String relayState;

    public SamlRequests(int port, TestRestTemplate restTemplate) {
        this.port = port;
        this.restTemplate = restTemplate;
    }

    public void httpRedirectSamlRequest(boolean signedRequest) throws TechnicalException, IOException {

        this.headers = new HttpHeaders();

        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(getUrlWithPort("/SAML2/SSO/Redirect"));

        AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination("https://localhost/SAML2/SSO/Redirect")
                .setForceAuthent(false).setIsPassive(false).setIssuer("http://client.ident.io/SAML2")
                .build();

        this.requestId = ar.getId();

        builder.queryParam("SAMLRequest", DecodeUtils.encode(ar.toString().getBytes(), true).get());

        // Build relayState
        this.relayState = UUID.randomUUID().toString();
        builder.queryParam("RelayState", this.relayState);

        if (signedRequest) {

            builder.queryParam("SigAlg", SamlConstants.SIGNATURE_ALG_RSA_SHA256);

            Signer signer = new Signer("src/test/resources/saml-sp-config/certificate.p12",
                    "password", false, SamlConstants.SIGNATURE_ALG_RSA_SHA256);

            String signedInfo = builder.build().encode().toUri().getRawQuery();

            byte[] signature = signer.signExternal(signedInfo);
            builder.queryParam("Signature", DecodeUtils.encode(signature, false).get());

        }

        ResponseEntity<String> request = this.restTemplate.exchange(
                builder.build().encode().toUri(),
                HttpMethod.GET,
                null,
                String.class);

        String redirectUrl = request.getHeaders().getFirst(HttpHeaders.LOCATION);

        assertEquals(HttpStatus.FOUND, request.getStatusCode());
        assertTrue(redirectUrl.startsWith(getUrlWithPort(AUTHENTICATION_URL)));

        String sessionCookie = getSessionCookie(request);
        String transactionId = getTransactionId(redirectUrl);

        assertTrue(sessionCookie.startsWith("identioSession="));
        assertNotNull(transactionId);

        // Request authentication methods
        this.headers = new HttpHeaders();
        this.headers.add(HttpHeaders.COOKIE, sessionCookie);
        this.headers.add("X-Transaction-ID", transactionId);
    }

    public void httpPostSamlRequest(boolean signedRequest) throws TechnicalException {

        MultiValueMap<String, String> payload = new LinkedMultiValueMap<>();

        AuthentRequest ar = AuthentRequestBuilder.getInstance().setDestination("https://localhost/SAML2/SSO/POST")
                .setForceAuthent(false).setIsPassive(false).setIssuer("http://client.ident.io/SAML2")
                .build();

        this.requestId = ar.getId();
        payload.add("SAMLRequest", ar.toBase64());

        // Build relayState
        this.relayState = UUID.randomUUID().toString();
        payload.add("RelayState", this.relayState);

        if (signedRequest) {
            Signer signer = new Signer("src/test/resources/saml-sp-config/certificate.p12",
                    "password", false, SamlConstants.SIGNATURE_ALG_RSA_SHA256);

            signer.signEmbedded(ar);
        }

        this.headers = new HttpHeaders();
        this.headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        ResponseEntity<String> request = this.restTemplate.exchange(
                "/SAML2/SSO/POST",
                HttpMethod.POST,
                new HttpEntity<>(payload, headers),
                String.class);

        String redirectUrl = request.getHeaders().getFirst(HttpHeaders.LOCATION);

        assertEquals(HttpStatus.FOUND, request.getStatusCode());
        assertTrue(redirectUrl.startsWith(getUrlWithPort(AUTHENTICATION_URL)));

        String sessionCookie = getSessionCookie(request);
        String transactionId = getTransactionId(redirectUrl);

        assertTrue(sessionCookie.startsWith("identioSession="));
        assertNotNull(transactionId);

        // Request authentication methods
        this.headers = new HttpHeaders();
        this.headers.add(HttpHeaders.COOKIE, sessionCookie);
        this.headers.add("X-Transaction-ID", transactionId);

    }

    public void getAuthMethods() {

        ResponseEntity<AuthMethodResponse[]> authMethodResponse = this.restTemplate.exchange(
                "/api/auth/methods",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                AuthMethodResponse[].class);

        assertEquals(HttpStatus.OK, authMethodResponse.getStatusCode());
        assertEquals(1, authMethodResponse.getBody().length);
        assertEquals("Local", authMethodResponse.getBody()[0].getName());
        assertEquals("local", authMethodResponse.getBody()[0].getType());

    }

    public void authenticateLocal() throws TechnicalException, InvalidAuthentResponseException {

        AuthSubmitRequest authenticationSubmit = new AuthSubmitRequest().setLogin("johndoe").setPassword("password")
                .setMethod("Local");

        ResponseEntity<AuthSubmitResponse> authSubmitResponseEntity = this.restTemplate.exchange(
                "/api/auth/submit/password",
                HttpMethod.POST,
                new HttpEntity<>(authenticationSubmit, this.headers),
                AuthSubmitResponse.class);

        // Check that the authentication is successful and that we're asked for consent
        AuthSubmitResponse authSubmitResponse = authSubmitResponseEntity.getBody();

        assertEquals(HttpStatus.OK, authSubmitResponseEntity.getStatusCode());
        assertEquals(ApiResponseStatus.RESPONSE, authSubmitResponse.getStatus());

        // Parse SAML Response
        String samlResponse = new String(Base64.getDecoder().decode(authSubmitResponse.getResponseData().getData()));
        this.ar = AuthentResponseBuilder.getInstance().build(samlResponse);

        // Parse RelayState
        String responseRelayState = authSubmitResponse.getResponseData().getRelayState();
        assertEquals(this.relayState, responseRelayState);

        // Parse responseUrl
        this.responseUrl = authSubmitResponse.getResponseData().getUrl();

    }

    public void validateResponse() throws InvalidAssertionException, TechnicalException, UntrustedSignerException, InvalidSignatureException, NoSuchAlgorithmException, UnsignedSAMLObjectException {

        // Check responseUrl
        assertEquals("http://client.ident.io/SAML2/POST", responseUrl);

        // Check response
        assertEquals("https://localhost/SAML2", ar.getIssuer());
        assertEquals(SamlConstants.STATUS_SUCCESS, ar.getStatusCode());
        assertEquals(null, ar.getStatusMessage());
        assertEquals("http://client.ident.io/SAML2/POST", ar.getDestination());
        assertEquals(true, ar.isSigned());

        // Check assertion
        Assertion as = ar.getAssertion();

        assertEquals("https://localhost/SAML2", as.getIssuer());
        assertEquals("johndoe", as.getSubjectNameID());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", as.getSubjectNameIDFormat());
        assertEquals(this.requestId, as.getInResponseTo());
        assertEquals("http://client.ident.io/SAML2/POST", as.getRecipient());
        assertEquals("urn:identio:auth-level:medium", as.getAuthnContext());
        assertEquals("http://client.ident.io/SAML2", as.getAudienceRestriction());

        // Check Response signature
        Metadata idpMetadata = MetadataBuilder.build(new File("src/test/resources/saml-sp-config/identio-idp-metadata.xml"));

        Validator validator = new Validator(idpMetadata.getIdpSsoDescriptors().get(0).getSigningCertificates(), false);
        validator.checkConditions(as);
        validator.validate(ar);
    }

    private String getUrlWithPort(String url) {

        return "http://localhost:" + this.port + url;
    }

    private String getSessionCookie(ResponseEntity<?> response) {

        return response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
    }

    private String getTransactionId(String url) {

        return url.substring(getUrlWithPort(AUTHENTICATION_URL).length());
    }
}
