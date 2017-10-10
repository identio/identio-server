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
import net.identio.server.service.oauth.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;

@Service
public class ClientCredentialsService {

    private static final Logger LOG = LoggerFactory.getLogger(ClientCredentialsService.class);

    @Autowired
    private OAuthClientRepository clientRepository;

    @Autowired
    private OAuthResponseService oAuthResponseService;

    @Autowired
    private AuthorizationService authorizationService;

    public Result<AccessTokenResponse> validateClientCredentialsRequest(
            ClientCredentialsRequest request, String authorization) {

        // Fetch and verify client identity
        OAuthClient client;
        Result<OAuthClient> oAuthClientResult = clientRepository.getClientFromAuthorization(authorization);

        if (oAuthClientResult.isSuccess()) {
            client = oAuthClientResult.get();
        } else {
            return Result.unauthorized(OAuthErrors.INVALID_CLIENT);
        }

        // Check that the client is authorized to use the authorization code grant
        if (!isClientCredentialsGrantAuthorizedForClient(client))
            return Result.fail(OAuthErrors.UNAUTHORIZED_CLIENT);

        // Check that the provided scopes were authorized in the previous request
        Result<LinkedHashMap<String, AuthorizationScope>> scopeResult =
                validateRequestedScopes(request.getScope(), client.getAllowedScopes());

        if (!scopeResult.isSuccess())
            return Result.fail(OAuthErrors.INVALID_SCOPE);

        // Everything's ok, generate response
        Result<AccessTokenResponse> accessTokenResponse = oAuthResponseService.generateTokenResponse(scopeResult.get().values(),
                client.getClientId(), null, false);

        if (!accessTokenResponse.isSuccess())
            return Result.serverError();

        return Result.success(accessTokenResponse.get());
    }

    private Result<LinkedHashMap<String, AuthorizationScope>> validateRequestedScopes(String requestedScopes, List<String> grantedScopes) {

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

    private boolean isClientCredentialsGrantAuthorizedForClient(OAuthClient client) {

        if (!client.getAllowedGrants().contains(OAuthGrants.CLIENT_CREDENTIALS)) {
            LOG.error("Client not authorized to use the client credentials grant");
            return false;
        }

        return true;
    }
}
