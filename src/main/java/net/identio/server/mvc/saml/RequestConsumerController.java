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
package net.identio.server.mvc.saml;

import net.identio.saml.SamlConstants;
import net.identio.server.exceptions.*;
import net.identio.server.model.SamlInboundRequest;
import net.identio.server.mvc.common.TransparentAuthController;
import net.identio.server.service.orchestration.RequestOrchestrationService;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.service.orchestration.model.ValidationStatus;
import net.identio.server.service.orchestration.model.RequestValidationResult;
import net.identio.server.utils.DecodeUtils;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.zip.DataFormatException;

@Controller
public class RequestConsumerController {

    private static final Logger LOG = LoggerFactory.getLogger(RequestConsumerController.class);

    @Autowired
    private RequestOrchestrationService validationService;
    @Autowired
    private TransparentAuthController transparentAuthController;
    @Autowired
    private ResponderController responderController;

    @RequestMapping(value = "/SAML2/SSO/POST", method = RequestMethod.POST)
    public String samlConsumerPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
                                   @RequestParam("SAMLRequest") String usSamlRequest,
                                   @RequestParam(value = "RelayState", required = false) String usRelayState,
                                   @CookieValue(required = false) String identioSession) throws ServerException, ValidationException, WebSecurityException {

        String decodedSamlRequest;
        String decodedRelayState;

        LOG.debug("Received request on /SAML2/SSO/POST");
        LOG.debug("* SAMLRequest: {}", usSamlRequest);
        LOG.debug("* RelayState: {}", usRelayState);

        // The SAML request is Base-64 encoded
        try {
            decodedSamlRequest = new String(DecodeUtils.decode(usSamlRequest, false));
        } catch (Base64DecodingException | IOException | DataFormatException e) {
            throw new ServerException("Error when decoding SAML Request", e);
        }

        // To prevent XSS attacks, we escape the RelayState value
        decodedRelayState = HtmlUtils.htmlEscape(usRelayState);

        return processRequest(httpRequest, httpResponse, SamlConstants.BINDING_HTTP_POST, decodedSamlRequest,
                decodedRelayState, null, null, null, identioSession);

    }

    @RequestMapping(value = "/SAML2/SSO/Redirect", method = RequestMethod.GET)
    public String samlConsumerRedirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
                                       @RequestParam("SAMLRequest") String usSamlRequest,
                                       @RequestParam(value = "RelayState", required = false) String usRelayState,
                                       @RequestParam(value = "SigAlg", required = false) String usSigAlg,
                                       @RequestParam(value = "Signature", required = false) String usSignature,
                                       @CookieValue(required = false) String identioSession) throws ServerException, ValidationException, WebSecurityException {

        String signedInfo = null;
        String decodedSamlRequest = null;
        String decodedRelayState = null;

        LOG.debug("Received request on /SAML2/SSO/Redirect");
        LOG.debug("* SAMLRequest: {}", usSamlRequest);
        LOG.debug("* RelayState: {}", usRelayState);
        LOG.debug("* SigAlg: {}", usSigAlg);
        LOG.debug("* Signature: {}", usSignature);

        if (usSignature != null) {

            // The signature is based on the URL-encoded values. As Spring does
            // the conversion automatically, we have to extract the values from
            // the query string
            String[] queryString = httpRequest.getQueryString().split("&");

            String encodedSamlRequest = null;
            String encodedRelayState = null;
            String encodedSigAlg = null;

            for (String element : queryString) {

                LOG.debug("Query string parameter: {}", element);

                if (element.startsWith("SAMLRequest"))
                    encodedSamlRequest = element;
                if (element.startsWith("RelayState"))
                    encodedRelayState = element;
                if (element.startsWith("SigAlg"))
                    encodedSigAlg = element;
            }

            if (encodedRelayState != null) {
                signedInfo = encodedSamlRequest + "&" + encodedRelayState + "&" + encodedSigAlg;
            } else {
                signedInfo = encodedSamlRequest + "&" + encodedSigAlg;
            }

            LOG.debug("Signed Info: {}", signedInfo);
        }

        // The SAML request is Base-64 encoded and deflated
        try {
            decodedSamlRequest = new String(DecodeUtils.decode(usSamlRequest, true));
        } catch (IOException | Base64DecodingException | DataFormatException e) {
            throw new ServerException("Error when decoding SAML Request", e);
        }

        // To prevent XSS attacks, we escape the RelayState value
        decodedRelayState = HtmlUtils.htmlEscape(usRelayState);

        return processRequest(httpRequest, httpResponse, SamlConstants.BINDING_HTTP_REDIRECT, decodedSamlRequest,
                decodedRelayState, usSigAlg, usSignature, signedInfo, identioSession);

    }

    private String processRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String binding,
                                  String request, String relayState, String sigAlg, String signatureValue, String signedInfo,
                                  String sessionId) throws ServerException, ValidationException, WebSecurityException {

        LOG.debug("Processing SAML authentication request.");

        SamlInboundRequest samlRequest = new SamlInboundRequest(binding, request, signatureValue, signedInfo, sigAlg,
                relayState);

        // The request is forwarded to the orchestration service
        RequestValidationResult result = validationService.validateRequest(samlRequest, sessionId);

        if (result.getValidationStatus() == ValidationStatus.RESPONSE) {

            return responderController.displayResponderPage(
                    result.getResponseData().getUrl(), result.getResponseData().getData(),
                    result.getResponseData().getRelayState(), result.getSessionId(), httpResponse);

        } else {
            return transparentAuthController.checkTransparentAuthentication(httpRequest, httpResponse,
                    result.getSessionId(), result.getTransactionId());
        }

    }
}
