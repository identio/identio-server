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
import net.identio.server.boot.GlobalConfiguration;
import net.identio.server.model.Result;
import net.identio.server.model.SamlInboundRequest;
import net.identio.server.mvc.common.StandardPages;
import net.identio.server.mvc.common.TransparentAuthController;
import net.identio.server.service.orchestration.RequestOrchestrationService;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.service.orchestration.model.RequestValidationResult;
import net.identio.server.service.saml.model.SamlErrors;
import net.identio.server.utils.DecodeUtils;
import net.identio.server.utils.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class RequestConsumerController {

    private static final Logger LOG = LoggerFactory.getLogger(RequestConsumerController.class);

    @Autowired
    private RequestOrchestrationService validationService;
    @Autowired
    private TransparentAuthController transparentAuthController;
    @Autowired
    private ResponderController responderController;
    @Autowired
    private GlobalConfiguration config;

    @RequestMapping(value = "/SAML2/SSO/POST", method = RequestMethod.POST)
    public String samlConsumerPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
                                   @RequestParam MultiValueMap<String, String> allParams,
                                   @CookieValue(required = false) String identioSession) throws ServerException, ValidationException, WebSecurityException {

        String decodedSamlRequest;
        String decodedRelayState;

        Result<String> samlRequest = HttpUtils.getUniqueParam(allParams, "SAMLRequest");
        Result<String> relayState = HttpUtils.getUniqueParam(allParams, "RelayState");

        if (!samlRequest.isSuccess() ||
                !relayState.isSuccess()
                )
            return StandardPages.errorPage(SamlErrors.INVALID_REQUEST);

        if (samlRequest.get() == null) return "redirect:/#!/error/" + SamlErrors.INVALID_REQUEST;

        // The SAML request is Base-64 encoded
        Result<byte[]> samlRequestDecodeResult = DecodeUtils.decode(samlRequest.get(), false);

        if (samlRequestDecodeResult.isSuccess()) {
            decodedSamlRequest = new String(samlRequestDecodeResult.get());
        } else {
            return StandardPages.errorPage(SamlErrors.INVALID_REQUEST);
        }

        // To prevent XSS attacks, we escape the RelayState value
        decodedRelayState = HtmlUtils.htmlEscape(relayState.get());

        return processRequest(httpRequest, httpResponse, SamlConstants.BINDING_HTTP_POST, decodedSamlRequest,
                decodedRelayState, null, null, null, identioSession);

    }

    @RequestMapping(value = "/SAML2/SSO/Redirect", method = RequestMethod.GET)
    public String samlConsumerRedirect(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
                                       @RequestParam MultiValueMap<String, String> allParams,
                                       @CookieValue(required = false) String identioSession) throws ServerException, ValidationException, WebSecurityException {

        String signedInfo = null;
        String decodedSamlRequest;
        String decodedRelayState;

        Result<String> samlRequest = HttpUtils.getUniqueParam(allParams, "SAMLRequest");
        Result<String> relayState = HttpUtils.getUniqueParam(allParams, "RelayState");
        Result<String> sigAlg = HttpUtils.getUniqueParam(allParams, "SigAlg");
        Result<String> signature = HttpUtils.getUniqueParam(allParams, "Signature");

        if (!samlRequest.isSuccess() ||
                !relayState.isSuccess() ||
                !sigAlg.isSuccess() ||
                !signature.isSuccess()
                )
            return StandardPages.errorPage(SamlErrors.INVALID_REQUEST);

        if (samlRequest.get() == null) return "redirect:/#!/error/" + SamlErrors.INVALID_REQUEST;

        if (signature.get() != null) {

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
        }

        // The SAML request is Base-64 encoded and deflated
        Result<byte[]> samlRequestDecodeResult = DecodeUtils.decode(samlRequest.get(), true);

        if (samlRequestDecodeResult.isSuccess()) {
            decodedSamlRequest = new String(samlRequestDecodeResult.get());
        } else {
            return StandardPages.errorPage(SamlErrors.INVALID_REQUEST);
        }

        // To prevent XSS attacks, we escape the RelayState value
        decodedRelayState = HtmlUtils.htmlEscape(relayState.get());

        return processRequest(httpRequest, httpResponse, SamlConstants.BINDING_HTTP_REDIRECT, decodedSamlRequest,
                decodedRelayState, sigAlg.get(), signature.get(), signedInfo, identioSession);

    }

    private String processRequest(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String binding,
                                  String request, String relayState, String sigAlg, String signatureValue, String signedInfo,
                                  String sessionId) throws ServerException, ValidationException, WebSecurityException {

        SamlInboundRequest samlRequest = new SamlInboundRequest(binding, request, signatureValue, signedInfo, sigAlg,
                relayState);

        // The request is forwarded to the orchestration service
        RequestValidationResult result = validationService.validateRequest(samlRequest, sessionId);

        switch (result.getValidationStatus()) {

            case RESPONSE:
                return responderController.displayResponderPage(
                        result.getResponseData().getUrl(), result.getResponseData().getData(),
                        result.getResponseData().getRelayState(), result.getSessionId(), httpResponse);
            case CONSENT:
                return StandardPages.consentPage(httpResponse, result.getSessionId(), result.getTransactionId(), config.isSecure());
            case ERROR:
                return StandardPages.errorPage(result.getErrorStatus());
            default:
                return transparentAuthController.checkTransparentAuthentication(httpRequest, httpResponse,
                        result.getSessionId(), result.getTransactionId());
        }
    }
}
