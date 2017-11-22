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
package net.identio.server.service.authentication;

import net.identio.server.exceptions.UnknownAuthMethodException;
import net.identio.server.model.*;
import net.identio.server.service.authentication.model.Authentication;
import net.identio.server.service.authentication.model.AuthenticationResult;
import net.identio.server.service.authentication.model.AuthenticationResultStatus;
import net.identio.server.service.authentication.saml.SamlAuthMethod;
import net.identio.server.service.transaction.model.TransactionData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

@Service
public class AuthenticationService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationService.class);

    private HashMap<AuthMethod, AuthenticationProvider> explicitAuthenticationProviders = new HashMap<>();
    private HashMap<AuthMethod, AuthenticationProvider> transparentAuthenticationProviders = new HashMap<>();
    private HashMap<String, AuthMethod> authMethods = new HashMap<>();

    public void registerExplicit(AuthMethod authMethod, AuthenticationProvider provider) throws IllegalArgumentException {

        LOG.info("Registering explicit method {}", authMethod.getName());

        if (explicitAuthenticationProviders.containsKey(authMethod)) {
            String message = "Authentication method name already in use";
            LOG.error(message);
            throw new IllegalArgumentException(message);
        }

        explicitAuthenticationProviders.put(authMethod, provider);
        authMethods.put(authMethod.getName(), authMethod);
    }

    public void registerTransparent(AuthMethod authMethod, AuthenticationProvider provider) throws IllegalArgumentException {

        LOG.info("Registering transparent method {}", authMethod.getName());

        if (transparentAuthenticationProviders.containsKey(authMethod)) {
            String message = "Authentication method name already in use";
            LOG.error(message);
            throw new IllegalArgumentException(message);
        }

        transparentAuthenticationProviders.put(authMethod, provider);
        authMethods.put(authMethod.getName(), authMethod);
    }

    public AuthenticationResult validateTransparent(Authentication authentication) {

        AuthenticationResult result = null;

        for (AuthMethod authMethod : transparentAuthenticationProviders.keySet()) {

            AuthenticationProvider provider = transparentAuthenticationProviders.get(authMethod);

            if (provider.accepts(authentication)) {
                result = provider.validate(authMethod, authentication);

                if (result.getStatus() != AuthenticationResultStatus.FAIL) {
                    break;
                }

            }
        }

        return result;
    }

    public AuthenticationResult validateExplicit(AuthMethod authMethod, Authentication authentication) {

        AuthenticationResult result = null;

        AuthenticationProvider provider = explicitAuthenticationProviders.get(authMethod);

        if (provider.accepts(authentication)) {
            result = provider.validate(authMethod, authentication);
        }

        return result;
    }

    public AuthMethod getAuthMethodByName(String name) throws UnknownAuthMethodException {

        AuthMethod authMethod = authMethods.get(name);

        if (authMethod == null) {
            throw new UnknownAuthMethodException("Unknown authentication method requested: " + name);
        }

        return authMethod;
    }


    public HashSet<AuthMethod> determineTargetAuthMethods(ArrayList<AuthLevel> targetAuthLevels) {

        HashSet<AuthMethod> nextAuthMethods = new HashSet<>();

        for (AuthMethod authMethod : authMethods.values()) {

            if (authMethod instanceof SamlAuthMethod) {

                // Check if the authentication level is supported
                HashMap<AuthLevel, String> outMap = ((SamlAuthMethod) authMethod).getSamlAuthMap().getOut();

                for (AuthLevel targetAuthLevel : targetAuthLevels) {
                    if (outMap.containsKey(targetAuthLevel)) {
                        nextAuthMethods.add(authMethod);
                        break;
                    }
                }
                continue;
            }

            if (targetAuthLevels.contains(authMethod.getAuthLevel())) {
                nextAuthMethods.add(authMethod);
            }
        }

        return nextAuthMethods;
    }

    public String getLogo(String authMethodName) {

        try {
            return getAuthMethodByName(authMethodName).getLogoFileName();
        } catch (UnknownAuthMethodException e) {
            return null;
        }
    }
}
