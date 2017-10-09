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
import net.identio.server.mvc.oauth.model.AccessTokenErrorResponse;
import net.identio.server.service.oauth.AuthorizationCodeService;
import net.identio.server.service.oauth.RefreshTokenService;
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
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

        OAuthInboundRequest request = new OAuthInboundRequest(clientId, responseType, redirectUri, scopes, state);

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
    public ResponseEntity<?> accessTokenRequest(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        Result<AccessTokenResponse> result = authorizationCodeService.validateTokenRequest(
                new AuthorizationCodeRequest().setGrantType(grantType).setCode(code).setRedirectUri(redirectUri), authorization);

        switch (result.getResultStatus()) {
            case FAIL:
                return new ResponseEntity<>(
                        new AccessTokenErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.BAD_REQUEST);
            default:
            case SERVER_ERROR:
                return new ResponseEntity<>(
                        new AccessTokenErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.INTERNAL_SERVER_ERROR);
            case UNAUTHORIZED:
                return new ResponseEntity<>(
                        new AccessTokenErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.UNAUTHORIZED);
            case OK:
                return new ResponseEntity<>(result.get(), HttpStatus.OK);
        }
    }

    @RequestMapping(value = "/oauth/token", method = RequestMethod.POST, params = "refresh_token")
    public ResponseEntity<?> refreshTokenRequest(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestHeader(value = "Authorization", required = false) String authorization) {

        Result<AccessTokenResponse> result = refreshTokenService.validateRefreshTokenRequest(
                new RefreshTokenRequest().setGrantType(grantType).setRefreshToken(refreshToken).setScope(scope), authorization);

        switch (result.getResultStatus()) {
            case FAIL:
                return new ResponseEntity<>(
                        new AccessTokenErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.BAD_REQUEST);
            default:
            case SERVER_ERROR:
                return new ResponseEntity<>(
                        new AccessTokenErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.INTERNAL_SERVER_ERROR);
            case UNAUTHORIZED:
                return new ResponseEntity<>(
                        new AccessTokenErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.UNAUTHORIZED);
            case OK:
                return new ResponseEntity<>(result.get(), HttpStatus.OK);
        }
    }
}