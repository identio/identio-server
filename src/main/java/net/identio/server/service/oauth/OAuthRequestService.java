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

import net.identio.server.model.*;
import net.identio.server.service.authorization.AuthorizationService;
import net.identio.server.service.authorization.exceptions.NoScopeProvidedException;
import net.identio.server.service.authorization.exceptions.UnknownScopeException;
import net.identio.server.service.oauth.infrastructure.OAuthClientRepository;
import net.identio.server.service.oauth.model.*;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import net.identio.server.service.orchestration.model.RequestParsingStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class OAuthRequestService {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthRequestService.class);

    @Autowired
    private OAuthClientRepository clientRepository;

    @Autowired
    private AuthorizationService authorizationService;

    public RequestParsingInfo validateAuthentRequest(OAuthInboundRequest request) {

        RequestParsingInfo result = new RequestParsingInfo();

        result.setProtocolType(ProtocolType.OAUTH);

        // Handle state and copy it in the response
        if (request.getState() != null) {
            result.setRelayState(request.getState());
        }

        // Fetch client
        OAuthClient client = clientRepository.getOAuthClientbyId(request.getClientId());
        if (client == null) {
            return result.setStatus(RequestParsingStatus.FATAL_ERROR).setErrorStatus(OAuthErrors.UNKNOWN_CLIENT);
        }

        // Verify redirectUri
        String redirectUri = client.getResponseUri().get(0);

        if (request.getRedirectUri() != null) {
            if (checkRedirectUri(client, request.getRedirectUri())) {
                redirectUri = request.getRedirectUri();
            } else {
                return result.setStatus(RequestParsingStatus.FATAL_ERROR).setErrorStatus(OAuthErrors.UNKNOWN_REDIRECT_URI);
            }
        }

        // Validate response type value
        if (request.getResponseType() == null || !checkValidResponseTypes(request.getResponseType())) {
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(OAuthErrors.RESPONSE_TYPE_NOT_SUPPORTED)
                    .setResponseUrl(redirectUri);
        }

        // Validate scope value
        LinkedHashMap<String, AuthorizationScope> scopes;
        try {
            scopes = authorizationService.deserializeScope(request.getScope());
        } catch (UnknownScopeException | NoScopeProvidedException e) {
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(OAuthErrors.INVALID_SCOPE).setResponseUrl(redirectUri);
        }

        // Validate client authorization regarding allowed scopes and response
        // types
        if (!checkClientAuthorization(client, request.getResponseType(), scopes.values())) {
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(OAuthErrors.UNAUTHORIZED_CLIENT).setResponseUrl(redirectUri);
        }

        result.setStatus(RequestParsingStatus.OK).setSourceApplication(client.getClientId()).setResponseUrl(redirectUri)
                .setRequestedScopes(scopes).setResponseType(request.getResponseType()).setConsentNeeded(client.isConsentNeeded());

        return result;
    }

    private boolean checkValidResponseTypes(String responseType) {

        // Only valid response types are "token" and "code"
        if (!responseType.equals(OAuthResponseType.CODE) && !responseType.equals(OAuthResponseType.TOKEN)) {
            LOG.error("ResponseType not supported: {}", responseType);
            return false;
        }

        return true;
    }

    private boolean checkRedirectUri(OAuthClient client, String redirectUri) {

        if (!client.getResponseUri().contains(redirectUri)) {
            LOG.error("Unknown redirectUri: {}", redirectUri);
            return false;
        }

        return true;
    }

    private boolean checkClientAuthorization(OAuthClient client, String responseType, Collection<AuthorizationScope> requestedScopes) {

        if (responseType.equals(OAuthResponseType.TOKEN) && !client.getAllowedGrants().contains(OAuthGrants.TOKEN)
                || responseType.equals(OAuthResponseType.CODE)
                && !client.getAllowedGrants().contains(OAuthGrants.AUTHORIZATION_CODE)) {

            LOG.error("Client not authorized to use the response type: {}", responseType);
            return false;
        }

        for (AuthorizationScope scope : requestedScopes) {
            if (!client.getAllowedScopes().contains(scope.getName())) {

                LOG.error("Client not authorized to use the requested scope");
                return false;
            }
        }

        return true;
    }
}
