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
package net.identio.server.mvc.oauth;

import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.model.OAuthInboundRequest;
import net.identio.server.mvc.common.TransparentAuthController;
import net.identio.server.service.orchestration.RequestOrchestrationService;
import net.identio.server.service.orchestration.model.RequestValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class AuthorizeController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizeController.class);

    @Autowired
    private RequestOrchestrationService validationService;

    @Autowired
    private TransparentAuthController transparentAuthController;

    @RequestMapping(value = "/oauth/authorize", method = RequestMethod.GET)
    public String authorizeRequest(
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scopes,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            @CookieValue(required = false) String identioSession,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) throws ValidationException, ServerException, WebSecurityException {

        LOG.info("Received OAuth authorization request from ClientId: {}", clientId);
        LOG.debug("RT: {} - RU: {} - SC: {} - ST: {}", responseType, redirectUri, scopes, state);

        OAuthInboundRequest request = new OAuthInboundRequest().setClientId(clientId).setResponseType(responseType)
                .setRedirectUri(redirectUri).setScope(scopes).setState(state).setCodeChallenge(codeChallenge)
                .setCodeChallengeMethod(codeChallengeMethod);

        RequestValidationResult result = validationService.validateRequest(request, identioSession);

        switch (result.getValidationStatus()) {
            case RESPONSE:
                return "redirect:" + result.getResponseData().getUrl();

            case CONSENT:
                return "redirect:/#!/consent/" + result.getTransactionId();

            case ERROR:
                return "redirect:/#!/error/" + result.getErrorStatus();

            default:
                return transparentAuthController.checkTransparentAuthentication(
                        httpRequest, httpResponse, result.getSessionId(), result.getTransactionId());
        }
    }
}