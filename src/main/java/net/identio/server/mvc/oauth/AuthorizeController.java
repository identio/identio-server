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

import net.identio.server.boot.GlobalConfiguration;
import net.identio.server.model.Result;
import net.identio.server.mvc.common.StandardPages;
import net.identio.server.service.oauth.model.OAuthErrors;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.model.OAuthInboundRequest;
import net.identio.server.mvc.common.TransparentAuthController;
import net.identio.server.service.orchestration.RequestOrchestrationService;
import net.identio.server.service.orchestration.model.RequestValidationResult;
import net.identio.server.utils.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
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
    @Autowired
    private GlobalConfiguration config;

    @RequestMapping(value = "/oauth/authorize", method = RequestMethod.GET)
    public String authorizeRequest(
            @RequestParam MultiValueMap<String, String> allParams,
            @CookieValue(required = false) String identioSession,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) throws ValidationException, ServerException, WebSecurityException {

        Result<String> responseType = HttpUtils.getUniqueParam(allParams, "response_type");
        Result<String> clientId = HttpUtils.getUniqueParam(allParams, "client_id");
        Result<String> redirectUri = HttpUtils.getUniqueParam(allParams, "redirect_uri");
        Result<String> scopes = HttpUtils.getUniqueParam(allParams, "scope");
        Result<String> state = HttpUtils.getUniqueParam(allParams, "state");
        Result<String> codeChallenge = HttpUtils.getUniqueParam(allParams, "code_challenge");
        Result<String> codeChallengeMethod = HttpUtils.getUniqueParam(allParams, "code_challenge_method");

        if (!responseType.isSuccess() ||
                !clientId.isSuccess() ||
                !redirectUri.isSuccess() ||
                !scopes.isSuccess() ||
                !state.isSuccess() ||
                !codeChallenge.isSuccess() ||
                !codeChallengeMethod.isSuccess()
                )
            return "redirect:/#!/error/" + OAuthErrors.INVALID_REQUEST;


        LOG.info("Received OAuth authorization request from ClientId: {}", clientId);
        LOG.debug("RT: {} - RU: {} - SC: {} - ST: {}", responseType, redirectUri, scopes, state);


        OAuthInboundRequest request = new OAuthInboundRequest().setClientId(clientId.get()).setResponseType(responseType.get())
                .setRedirectUri(redirectUri.get()).setScope(scopes.get()).setState(state.get())
                .setCodeChallenge(codeChallenge.get()).setCodeChallengeMethod(codeChallengeMethod.get());

        RequestValidationResult result = validationService.validateRequest(request, identioSession);

        switch (result.getValidationStatus()) {

            case RESPONSE:
                return "redirect:" + result.getResponseData().getUrl();
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