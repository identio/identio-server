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
package net.identio.server.service.authorization;

import net.identio.server.model.AuthorizationScope;
import net.identio.server.service.authorization.exceptions.NoScopeProvidedException;
import net.identio.server.service.authorization.exceptions.UnknownScopeException;
import net.identio.server.service.configuration.ConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Service
public class AuthorizationService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);

    private HashMap<String, AuthorizationScope> scopes;

    @Autowired
    public AuthorizationService(ConfigurationService configurationService) {

        scopes = new HashMap<>();

        List<AuthorizationScope> configuredScopes = configurationService.getConfiguration().getAuthorizationConfiguration().getScopes();

        if (configuredScopes == null) {
            return;
        }

        LOG.info("Initializing Authorization Service");

        for (AuthorizationScope scope : configuredScopes) {
            scopes.put(scope.getName(), scope);
        }

    }

    public List<AuthorizationScope> getScopes(List<String> scopeNames) throws UnknownScopeException, NoScopeProvidedException {

        List<AuthorizationScope> scopeList = new ArrayList<>();

        if (scopeNames.isEmpty()) {
            throw new NoScopeProvidedException("Scope list is empty");
        }

        for (String scopeName : scopeNames) {
            if (scopes.containsKey(scopeName)) {
                scopeList.add(scopes.get(scopeName));
            } else {
                throw new UnknownScopeException("Unknown scope: " + scopeName);
            }
        }
        return scopeList;
    }

}
