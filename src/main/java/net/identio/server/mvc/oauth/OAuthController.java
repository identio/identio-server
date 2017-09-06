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

import net.identio.server.service.oauth.OAuthService;
import net.identio.server.service.oauth.model.ValidateTokenResult;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Controller
public class OAuthController {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthController.class);

    @Autowired
    private RequestOrchestrationService validationService;

    @Autowired
    private TransparentAuthController transparentAuthController;

    @Autowired
    private OAuthService oAuthService;

    @RequestMapping(value = "/oauth/authorize", method = RequestMethod.GET)
    public String authorizeRequest(
            @RequestParam(value = "response_type", required = false) String responseType,
            @RequestParam(value = "client_id", required = false) String clientId,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "scope", required = false) String scopes,
            @RequestParam(value = "state", required = false) String state,
            @CookieValue(required = false) String identioSession,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) throws ValidationException, ServerException, WebSecurityException {

        LOG.info("Received OAuth authorization request from ClientId: {}", clientId);
        LOG.debug("RT: {} - RU: {} - SC: {} - ST: {}", responseType, redirectUri, scopes, state);

        // Scopes are separated by a space

        List<String> scopesList = new ArrayList<>();
        if (scopes != null) {
            scopesList = Arrays.asList(scopes.split(" "));
        }

        OAuthInboundRequest request = new OAuthInboundRequest(clientId, responseType, redirectUri, scopesList, state);

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

    @RequestMapping(value = "/oauth/token", method = RequestMethod.POST)
    public String accessTokenRequest(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestHeader(value = "Authorization", required = false) String authorization) throws ValidationException, ServerException, WebSecurityException {

        ValidateTokenResult result = oAuthService.validateTokenRequest(grantType, code, redirectUri, authorization);

        return null;
    }
}