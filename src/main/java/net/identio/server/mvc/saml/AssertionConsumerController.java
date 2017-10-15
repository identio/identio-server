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

import net.identio.server.boot.GlobalConfiguration;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.service.authentication.saml.SamlAuthentication;
import net.identio.server.service.orchestration.AuthOrchestrationService;
import net.identio.server.service.orchestration.model.AuthenticationValidationResult;
import net.identio.server.service.orchestration.model.ValidationStatus;
import net.identio.server.utils.HttpUtils;
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

@Controller
public class AssertionConsumerController {

    private static final Logger LOG = LoggerFactory.getLogger(AssertionConsumerController.class);

    @Autowired
    private AuthOrchestrationService authOrchestrationService;

    @Autowired
    private GlobalConfiguration config;

    @Autowired
    private ResponderController responderController;

    @RequestMapping(value = "/SAML2/ACS/POST", method = RequestMethod.POST)
    public String samlConsumerPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
                                   @RequestParam("SAMLResponse") String usSamlResponse,
                                   @RequestParam(value = "RelayState", required = false) String usRelayState,
                                   @CookieValue String identioSession) throws ValidationException, ServerException, WebSecurityException {

        LOG.debug("Received SAML response on /SAML2/ACS/POST");
        LOG.debug("* SAMLResponse: {}", usSamlResponse);
        LOG.debug("* RelayState: {}", usRelayState);

        // To prevent XSS attacks, we escape the RelayState value
        String transactionId = HtmlUtils.htmlEscape(usRelayState);
        SamlAuthentication authentication = new SamlAuthentication(usSamlResponse);

        AuthenticationValidationResult result = authOrchestrationService
                .handleExplicitAuthentication(transactionId, identioSession, null, authentication);

        if (result.getValidationStatus() == ValidationStatus.RESPONSE) {

            return responderController.displayResponderPage(
                    result.getResponseData().getUrl(), result.getResponseData().getData(),
                    result.getResponseData().getRelayState(), identioSession, httpResponse);

        } else {
            LOG.debug("Displaying authentication page");

            HttpUtils.setSessionCookie(httpResponse, identioSession, config.isSecure());

            return "redirect:/#!/auth/" + transactionId;
        }

    }
}
