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
import net.identio.server.service.oauth.infrastructure.OAuthClientRepository;
import net.identio.server.service.oauth.infrastructure.RefreshTokenRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.RefreshTokenFetchException;
import net.identio.server.service.oauth.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Optional;

@Service
public class RefreshTokenService {

    private static final Logger LOG = LoggerFactory.getLogger(RefreshTokenService.class);

    @Autowired
    private OAuthClientRepository clientRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private OAuthResponseService oAuthResponseService;

    @Autowired
    private AuthorizationService authorizationService;

    public Result<AccessTokenResponse> validateRefreshTokenRequest(RefreshTokenRequest request, String authorization) {

        // Check that all parameters are correct
        if (!isRefreshTokenRequestValid(request))
            return Result.fail(OAuthErrors.INVALID_REQUEST);

        // Check grant type
        if (!isRefreshTokenGrantSupported(request.getGrantType()))
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
        if (!isRefreshTokenGrantAuthorizedForClient(client))
            return Result.fail(OAuthErrors.UNAUTHORIZED_CLIENT);

        // Fetch the refresh token code data
        RefreshToken refreshToken;
        try {
            Optional<RefreshToken> result = refreshTokenRepository.getAccessTokenByRefreshTokenValue(request.getRefreshToken());

            if (!result.isPresent()) {
                LOG.error("Unknown refresh token");
                return Result.fail(OAuthErrors.INVALID_GRANT);
            }

            refreshToken = result.get();

        } catch (RefreshTokenFetchException e) {
            return Result.serverError();
        }

        // Verify that the refresh token was generated for this client
        if (!isRefreshTokenGeneratedForClient(refreshToken, client))
            return Result.fail(OAuthErrors.INVALID_GRANT);

        // Check that the provided scopes were authorized in the previous request
        Result<LinkedHashMap<String, AuthorizationScope>> scopeResult =
                validateRequestedScopes(request.getScope(), refreshToken.getScope());

        if (!scopeResult.isSuccess())
            return Result.fail(OAuthErrors.INVALID_SCOPE);

        // Everything's ok, generate response
        Result<AccessTokenResponse> accessTokenResponse = oAuthResponseService.generateTokenResponse(scopeResult.get().values(),
                refreshToken.getClientId(), refreshToken.getUserId(), false);

        if (!accessTokenResponse.isSuccess())
            return Result.serverError();

        return Result.success(accessTokenResponse.get());
    }

    private Result<LinkedHashMap<String, AuthorizationScope>> validateRequestedScopes(String requestedScopes, String grantedScopes) {

        LinkedHashMap<String, AuthorizationScope> grantedScopesMap;
        LinkedHashMap<String, AuthorizationScope> requestedScopesMap;

        try {
            grantedScopesMap = authorizationService.deserializeScope(grantedScopes);

            // If no scope is provided, use the granted scopes
            if (requestedScopes == null) {
                return Result.success(grantedScopesMap);
            }

            // Verify each requested scope
            requestedScopesMap = authorizationService.deserializeScope(requestedScopes);

            if (!grantedScopesMap.keySet().containsAll(requestedScopesMap.keySet())) {
                LOG.error("One or more requested scopes were not authorized");
                return Result.fail();
            }

            return Result.success(requestedScopesMap);

        } catch (UnknownScopeException | NoScopeProvidedException e) {
            return Result.fail();
        }
    }

    private boolean isRefreshTokenGeneratedForClient(RefreshToken refreshToken, OAuthClient client) {

        if (!refreshToken.getClientId().equals(client.getClientId())) {
            LOG.error("Refresh token wasn't generated for clientId {} but for {}", client.getClientId(), refreshToken.getClientId());
            return false;
        }

        return true;
    }

    private boolean isRefreshTokenGrantAuthorizedForClient(OAuthClient client) {

        if (!client.getAllowedGrants().contains(OAuthGrants.REFRESH_TOKEN)) {
            LOG.error("Client not authorized to use the authorization code grant");
            return false;
        }

        return true;
    }

    private boolean isRefreshTokenGrantSupported(String grantType) {

        if (!OAuthGrants.REFRESH_TOKEN.equals(grantType)) {
            LOG.error("Unsupported grant: {}", grantType);
            return false;
        }

        return true;
    }

    private boolean isRefreshTokenRequestValid(RefreshTokenRequest request) {

        if (request.getGrantType() == null) {
            LOG.error("Missing grant_type parameter");
            return false;
        }
        if (request.getRefreshToken() == null) {
            LOG.error("Missing refresh_token parameter");
            return false;
        }
        return true;
    }
}
