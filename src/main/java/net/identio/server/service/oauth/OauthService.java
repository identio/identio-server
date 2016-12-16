/*
 This file is part of Ident.io

 Ident.io - A flexible authentication server
 Copyright (C) Loeiz TANGUY

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.identio.server.service.oauth;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import net.identio.server.model.AuthRequestValidationResult;
import net.identio.server.model.ErrorStatus;
import net.identio.server.model.OAuthClient;
import net.identio.server.model.OAuthInboundRequest;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.oauth.exceptions.ClientNotFoundException;
import net.identio.server.service.oauth.exceptions.InvalidRedirectUriException;
import net.identio.server.service.oauth.model.OAuthGrants;
import net.identio.server.service.oauth.model.OAuthResponseType;

@Service
@Scope("singleton")
public class OauthService {

	private OAuthClientRepository clientRepository;

	@Autowired
	public OauthService(OAuthClientRepository clientRepository) {
		this.clientRepository = clientRepository;
	}

	public AuthRequestValidationResult validateAuthentRequest(OAuthInboundRequest request)
			throws ClientNotFoundException, InvalidRedirectUriException {

		AuthRequestValidationResult result = new AuthRequestValidationResult();

		// Fetch client
		OAuthClient client;

		client = clientRepository.getOAuthClientbyId(request.getClientId());

		// Verify redirectUri
		if (!client.getResponseUri().contains(request.getRedirectUri())) {
			throw new InvalidRedirectUriException("Unknown redirectUri" + request.getRedirectUri());
		}

		// Validate response type value
		if (!checkValidResponseTypes(request.getResponseType())) {
			return result.setSuccess(false).setErrorStatus(ErrorStatus.OAUTH_RESPONSE_TYPE_NOT_SUPPORTED);
		}
		// Validate scope value
		if (!checkValidScopes(request.getScopes())) {
			return result.setSuccess(false).setErrorStatus(ErrorStatus.OAUTH_INVALID_SCOPE);
		}
		
		// Validate requested response type
		if (!request.getResponseType().equals(OAuthResponseType.TOKEN) && client.getAllowedGrants().contains(OAuthGrants.IMPLICIT)
				|| !request.getResponseType().equals(OAuthResponseType.CODE)
						&& client.getAllowedGrants().contains(OAuthGrants.AUTHORIZATION_CODE)) {
			return result.setSuccess(false).setErrorStatus(ErrorStatus.OAUTH_UNAUTHORIZED_CLIENT);
		}


		// Validate requested scopes
		if (!client.getAllowedScopes().containsAll(request.getScopes())) {
			return result.setSuccess(false).setErrorStatus(ErrorStatus.OAUTH_UNAUTHORIZED_CLIENT);
		}

		return result;
	}

	private boolean checkValidResponseTypes(String responseType) {

		// Only valid response types are "token" and "code"
		return responseType.equals(OAuthResponseType.CODE) || responseType.equals(OAuthResponseType.CODE);
	}

	private boolean checkValidScopes(List<String> scopes) {

		// TODO: to be implemented

		return true;
	}

}
