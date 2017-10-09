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

package net.identio.server.service.oauth;

import net.identio.server.model.AuthorizationScope;
import net.identio.server.model.Result;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.authorization.exceptions.NoScopeProvidedException;
import net.identio.server.service.authorization.exceptions.UnknownScopeException;
import net.identio.server.service.oauth.infrastructure.AuthorizationCodeRepository;
import net.identio.server.service.oauth.infrastructure.OAuthClientRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeDeleteException;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeFetchException;
import net.identio.server.service.oauth.model.*;
import net.identio.server.utils.MiscUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Optional;

@Service
public class AuthorizationCodeService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationCodeService.class);

    @Autowired
    private OAuthClientRepository clientRepository;

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private OAuthResponseService oAuthResponseService;

    @Autowired
    private AuthorizationService authorizationService;

    public Result<AccessTokenResponse> validateTokenRequest(AuthorizationCodeRequest request, String authorization) {

        // Check that all parameters are correct
        if (!isAuthorizationCodeRequestValid(request))
            return Result.fail(OAuthErrors.INVALID_REQUEST);

        // Check grant type
        if (!isAuthorizationCodeGrantSupported(request.getGrantType()))
            return Result.fail(OAuthErrors.UNSUPPORTED_GRANT_TYPE);

        // Fetch and verify client identity
        OAuthClient client;
        Result<OAuthClient> oAuthClientResult = clientRepository.getClientFromAuthorization(authorization);

        if (oAuthClientResult.isSuccess()) {
            client = oAuthClientResult.get();
        } else {
            return Result.unauthorized(OAuthErrors.INVALID_CLIENT);
        }

        // Check that the client is authorized to use the authorization code grant
        if (!isAuthorizationCodeGrantAuthorizedForClient(client))
            return Result.fail(OAuthErrors.UNAUTHORIZED_CLIENT);

        // Fetch the authorization code data
        AuthorizationCode code;
        try {
            Optional<AuthorizationCode> result = authorizationCodeRepository.getAuthorizationCodeByValue(request.getCode());

            if (!result.isPresent()) {
                LOG.error("Unknown authorization code");
                return Result.fail(OAuthErrors.INVALID_GRANT);
            }

            code = result.get();

        } catch (AuthorizationCodeFetchException e) {
            return Result.serverError();
        }

        // Verify that the authorization code exist and is not expired
        // Verify that the authorization code was generated for this client
        // Verify that the redirect url matches the one provided in the initial request
        if (!codeExistsAndIsValid(code) ||
                !isCodeGeneratedForClient(code, client) ||
                !redirectUriMatchesInitialRequest(code, request.getRedirectUri()))
            return Result.fail(OAuthErrors.INVALID_GRANT);

        // Everything's ok, generate response
        LinkedHashMap<String, AuthorizationScope> scopes;
        try {
            scopes = authorizationService.deserializeScope(code.getScope());
        } catch (UnknownScopeException | NoScopeProvidedException e) {
            return Result.fail(OAuthErrors.INVALID_GRANT);
        }

        Result<AccessTokenResponse> accessTokenResponse = oAuthResponseService.generateTokenResponse(scopes.values(),
                code.getClientId(), code.getUserId(),
                isRefreshTokenAuthorized(client));

        if (!accessTokenResponse.isSuccess())
            return Result.serverError();

        // Delete authorization code from repository
        try {
            authorizationCodeRepository.delete(code);
        } catch (AuthorizationCodeDeleteException e) {
            return Result.serverError();
        }

        return Result.success(accessTokenResponse.get());
    }

    private boolean isRefreshTokenAuthorized(OAuthClient client) {
        return client.getAllowedGrants().contains(OAuthGrants.REFRESH_TOKEN);
    }

    private boolean redirectUriMatchesInitialRequest(AuthorizationCode code, String redirectUri) {

        if (!MiscUtils.equalsWithNulls(code.getRedirectUrl(), redirectUri)) {
            LOG.error("Redirect uri {} doesn't match the initial redirect uri {}", redirectUri, code.getRedirectUrl());
            return false;
        }

        return true;
    }

    private boolean isCodeGeneratedForClient(AuthorizationCode authorizationCode, OAuthClient client) {

        if (!authorizationCode.getClientId().equals(client.getClientId())) {
            LOG.error("Authorization code wasn't generated for clientId {} but for {}", client.getClientId(), authorizationCode.getClientId());
            return false;
        }

        return true;
    }

    private boolean codeExistsAndIsValid(AuthorizationCode code) {

        if (code.getExpirationTime() < System.currentTimeMillis() / 1000) {
            LOG.error("Code is expired");
            return false;
        }

        return true;
    }

    private boolean isAuthorizationCodeGrantAuthorizedForClient(OAuthClient client) {

        if (!client.getAllowedGrants().contains(OAuthGrants.AUTHORIZATION_CODE)) {
            LOG.error("Client not authorized to use the authorization code grant");
            return false;
        }

        return true;
    }

    private boolean isAuthorizationCodeGrantSupported(String grantType) {

        if (!OAuthGrants.AUTHORIZATION_CODE.equals(grantType)) {
            LOG.error("Unsupported grant: {}", grantType);
            return false;
        }

        return true;
    }

    private boolean isAuthorizationCodeRequestValid(AuthorizationCodeRequest request) {

        if (request.getGrantType() == null) {
            LOG.error("Missing grant_type parameter");
            return false;
        }
        if (request.getCode() == null) {
            LOG.error("Missing code parameter");
            return false;
        }
        return true;
    }
}
