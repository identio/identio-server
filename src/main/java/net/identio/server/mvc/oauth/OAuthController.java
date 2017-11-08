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

import net.identio.server.model.Result;
import net.identio.server.mvc.oauth.model.OAuthApiErrorResponse;
import net.identio.server.service.oauth.AuthorizationCodeService;
import net.identio.server.service.oauth.ClientCredentialsService;
import net.identio.server.service.oauth.RefreshTokenService;
import net.identio.server.service.oauth.ResourceOwnerCredentialsService;
import net.identio.server.service.oauth.model.*;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

@Controller
public class OAuthController {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthController.class);

    @Autowired
    private RequestOrchestrationService validationService;

    @Autowired
    private TransparentAuthController transparentAuthController;

    @Autowired
    private AuthorizationCodeService authorizationCodeService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private ClientCredentialsService clientCredentialsService;

    @Autowired
    private ResourceOwnerCredentialsService resourceOwnerCredentialsService;

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

    @RequestMapping(value = "/oauth/token", method = RequestMethod.POST)
    public ResponseEntity<?> tokenRequest(
            @RequestParam MultiValueMap<String, String> allParams,
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        Result<String> grantTypeResult = getUniqueParam(allParams, "grant_type");

        if (!grantTypeResult.isSuccess() || grantTypeResult.get() == null) return badRequest();

        Result<AccessTokenResponse> result;

        switch (grantTypeResult.get()) {

            case OAuthGrants.AUTHORIZATION_CODE:
                result = authorizationCodeRequest(allParams, authorization);
                break;

            case OAuthGrants.REFRESH_TOKEN:
                result = refreshTokenRequest(allParams, authorization);
                break;

            case OAuthGrants.CLIENT_CREDENTIALS:
                result = clientCredentialsRequest(allParams, authorization);
                break;

            case OAuthGrants.PASSWORD:
                result = resourceOwnerCredentials(allParams, authorization);
                break;

            default:
                return new ResponseEntity<>(
                        new OAuthApiErrorResponse().setError(OAuthErrors.UNSUPPORTED_GRANT_TYPE),
                        HttpStatus.BAD_REQUEST);
        }

        switch (result.getResultStatus()) {
            case FAIL:
                return new ResponseEntity<>(
                        new OAuthApiErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.BAD_REQUEST);
            default:
            case SERVER_ERROR:
                return new ResponseEntity<>(
                        new OAuthApiErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.INTERNAL_SERVER_ERROR);
            case UNAUTHORIZED:
                return new ResponseEntity<>(
                        new OAuthApiErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.UNAUTHORIZED);
            case OK:
                return new ResponseEntity<>(result.get(), HttpStatus.OK);
        }
    }

    private Result<AccessTokenResponse> authorizationCodeRequest(MultiValueMap<String, String> allParams, String authorization) {

        Result<String> codeResult = getUniqueParam(allParams, "code");
        Result<String> redirectUriResult = getUniqueParam(allParams, "redirect_uri");
        Result<String> codeVerifierResult = getUniqueParam(allParams, "code_verifier");

        if (!redirectUriResult.isSuccess() || !codeResult.isSuccess() || !codeVerifierResult.isSuccess())
            return Result.fail(OAuthErrors.INVALID_REQUEST);

        return authorizationCodeService.validateTokenRequest(
                new AuthorizationCodeRequest().setCode(codeResult.get()).setRedirectUri(redirectUriResult.get())
                .setCodeVerifier(codeVerifierResult.get()), authorization);
    }

    private Result<AccessTokenResponse> refreshTokenRequest(MultiValueMap<String, String> allParams, String authorization) {

        Result<String> refreshTokenResult = getUniqueParam(allParams, "refresh_token");
        Result<String> scopeResult = getUniqueParam(allParams, "scope");

        if (!refreshTokenResult.isSuccess() || !scopeResult.isSuccess())
            return Result.fail(OAuthErrors.INVALID_REQUEST);

        return refreshTokenService.validateRefreshTokenRequest(
                new RefreshTokenRequest().setRefreshToken(refreshTokenResult.get()).setScope(scopeResult.get()), authorization);
    }

    private Result<AccessTokenResponse> clientCredentialsRequest(MultiValueMap<String, String> allParams, String authorization) {

        Result<String> scopeResult = getUniqueParam(allParams, "scope");

        if (!scopeResult.isSuccess()) return Result.fail(OAuthErrors.INVALID_REQUEST);

        return clientCredentialsService.validateClientCredentialsRequest(
                new ClientCredentialsRequest().setScope(scopeResult.get()), authorization);
    }

    private Result<AccessTokenResponse> resourceOwnerCredentials(MultiValueMap<String, String> allParams, String authorization) {

        Result<String> usernameResult = getUniqueParam(allParams, "username");
        Result<String> passwordResult = getUniqueParam(allParams, "password");
        Result<String> scopeResult = getUniqueParam(allParams, "scope");

        if (!usernameResult.isSuccess() || !passwordResult.isSuccess() || !scopeResult.isSuccess())
            return Result.fail(OAuthErrors.INVALID_REQUEST);

        return resourceOwnerCredentialsService.validateResourceOwnerCredentialsRequest(
                new ResourceOwnerCredentialsRequest().setUsername(usernameResult.get()).setPassword(passwordResult.get())
                        .setScope(scopeResult.get()), authorization);
    }


    private ResponseEntity<OAuthApiErrorResponse> badRequest() {
        return new ResponseEntity<>(
                new OAuthApiErrorResponse().setError(OAuthErrors.INVALID_REQUEST),
                HttpStatus.BAD_REQUEST);
    }

    private Result<String> getUniqueParam(MultiValueMap<String, String> allParams, String param) {

        List<String> paramList = allParams.getOrDefault(param, new ArrayList<>());

        if (paramList.size() > 1) return Result.fail();

        return paramList.size() == 1 ? Result.success(paramList.get(0)) : Result.success(null);
    }

}