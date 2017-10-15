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
package net.identio.server.mvc.common;

import net.identio.server.boot.GlobalConfiguration;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.service.authentication.model.X509Authentication;
import net.identio.server.mvc.saml.ResponderController;
import net.identio.server.service.orchestration.AuthOrchestrationService;
import net.identio.server.service.orchestration.model.AuthenticationValidationResult;
import net.identio.server.service.orchestration.model.ValidationStatus;
import net.identio.server.utils.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.cert.X509Certificate;

@Controller
public class TransparentAuthController {

    private static final Logger LOG = LoggerFactory.getLogger(TransparentAuthController.class);

    @Autowired
    private AuthOrchestrationService authOrchestrationService;
    @Autowired
    private ResponderController responderController;
    @Autowired
    private GlobalConfiguration config;

    public String checkTransparentAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
                                                 String sessionId, String transactionId)
            throws ServerException, WebSecurityException {

        // We check if the user was authenticated with a X509 certificate
        Object clientAuthCerts = httpRequest.getAttribute("javax.servlet.request.X509Certificate");

        String userCert = HttpUtils.getHttpHeader(httpRequest, "X-User-Cert");
        String sharedSecret = HttpUtils.getHttpHeader(httpRequest, "X-Shared-Secret");

        X509Authentication authentication;

        if (clientAuthCerts != null || userCert != null && sharedSecret != null) {
            authentication = new X509Authentication((X509Certificate[]) clientAuthCerts, userCert, sharedSecret);
        } else {
            return redirectToAuthenticationPage(httpResponse, sessionId, transactionId);
        }

        AuthenticationValidationResult result = authOrchestrationService.handleTransparentAuthentication(
                authentication, sessionId, transactionId);

        if (result.getValidationStatus() == ValidationStatus.RESPONSE) {

            return responderController.displayResponderPage(
                    result.getResponseData().getUrl(), result.getResponseData().getData(),
                    result.getResponseData().getRelayState(), sessionId, httpResponse);

        } else {
            return redirectToAuthenticationPage(httpResponse, sessionId, transactionId);
        }
    }

    private String redirectToAuthenticationPage(HttpServletResponse httpResponse, String sessionId,
                                                String transactionId) {
        LOG.debug("Displaying authentication page");

        HttpUtils.setSessionCookie(httpResponse, sessionId, config.isSecure());

        return "redirect:/#!/auth/" + transactionId;
    }

}
