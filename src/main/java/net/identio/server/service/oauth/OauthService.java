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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import net.identio.server.model.AuthRequestValidationResult;
import net.identio.server.model.OAuthInboundRequest;
import net.identio.server.model.OAuthResponseType;
import net.identio.server.model.RequestType;
import net.identio.server.service.configuration.ConfigurationService;

@Service
@Scope("singleton")
public class OauthService {

	private ConfigurationService configurationService;

	public OauthService(@Autowired ConfigurationService configurationService) {
		this.configurationService = configurationService;
	}

	public AuthRequestValidationResult validateAuthentRequest(OAuthInboundRequest request) {

		AuthRequestValidationResult result = new AuthRequestValidationResult();

		// Validate response type
		try {
			OAuthResponseType.valueOf(request.getResponseType());
		} catch (IllegalArgumentException e) {
			// TODO: handle error
		}
		// Verify clientId

		// Verify scope

		// Verify redirectUri

		return result;
	}

}
