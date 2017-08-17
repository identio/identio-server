/*
 This file is part of Ident.io.

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
package net.identio.server.service.authentication;

import net.identio.server.model.*;
import net.identio.server.service.authentication.model.Authentication;
import net.identio.server.service.authentication.model.AuthenticationResult;
import net.identio.server.service.authentication.model.AuthenticationResultStatus;
import net.identio.server.service.transaction.model.TransactionData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class AuthenticationService {

	private static final Logger LOG = LoggerFactory.getLogger(AuthenticationService.class);

	private HashMap<AuthMethod, AuthenticationProvider> explicitAuthenticationProviders = new HashMap<>();
	private HashMap<AuthMethod, AuthenticationProvider> transparentAuthenticationProviders = new HashMap<>();

	public void registerExplicit(AuthMethod authMethod, AuthenticationProvider provider) throws IllegalArgumentException {

		LOG.info("Registering explicit method {}", authMethod.getName());

		if (explicitAuthenticationProviders.containsKey(authMethod)) {
			String message = "Authentication method name already in use";
			LOG.error(message);
			throw new IllegalArgumentException(message);
		}

		explicitAuthenticationProviders.put(authMethod, provider);
	}

	public void registerTransparent(AuthMethod authMethod, AuthenticationProvider provider) throws IllegalArgumentException {

		LOG.info("Registering transparent method {}", authMethod.getName());
		
		if (transparentAuthenticationProviders.containsKey(authMethod.getName())) {
			String message = "Authentication method name already in use";
			LOG.error(message);
			throw new IllegalArgumentException(message);
		}

		transparentAuthenticationProviders.put(authMethod, provider);
	}

	public AuthenticationResult validateTransparent(Authentication authentication, TransactionData transactionData) {

		AuthenticationResult result = null;

		for (AuthMethod authMethod : transparentAuthenticationProviders.keySet()) {

			AuthenticationProvider provider = transparentAuthenticationProviders.get(authMethod);

			if (provider.accepts(authentication)) {
				result = provider.validate(authMethod, authentication, transactionData);

				if (result.getStatus() != AuthenticationResultStatus.FAIL) {
					break;
				}

			}
		}

		return result;
	}

	public AuthenticationResult validateExplicit(AuthMethod authMethod, Authentication authentication,
			TransactionData transactionData) {

		AuthenticationResult result = null;

		AuthenticationProvider provider = explicitAuthenticationProviders.get(authMethod);

		if (provider.accepts(authentication)) {
			result = provider.validate(authMethod, authentication, transactionData);
		}

		return result;
	}
}
