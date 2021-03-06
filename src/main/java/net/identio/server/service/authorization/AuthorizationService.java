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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthorizationService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);

    @Autowired
    private AuthorizationConfiguration config;

    public AuthorizationService() {

        LOG.info("Initializing Authorization Service");
    }

    public LinkedHashMap<String, AuthorizationScope> deserializeScope(String scope) throws UnknownScopeException, NoScopeProvidedException {

        List<String> scopeNames = scope != null ? Arrays.asList(scope.split(" ")): new ArrayList<>();

        return deserializeScope(scopeNames);
    }

    public LinkedHashMap<String, AuthorizationScope> deserializeScope(List<String> scope) throws UnknownScopeException, NoScopeProvidedException {

        LinkedHashMap<String, AuthorizationScope> result = new LinkedHashMap<>();

        if (scope.isEmpty()) {
            throw new NoScopeProvidedException("Scope list is empty");
        }

        for (String scopeName : scope) {
            if (config.getAllScopes().containsKey(scopeName)) {
                result.put(scopeName, config.getAllScopes().get(scopeName));
            } else {
                throw new UnknownScopeException("Unknown scope: " + scopeName);
            }
        }
        return result;
    }

    public String serializeScope(Collection<AuthorizationScope> scopes) {

        return scopes.stream()
                .map(AuthorizationScope::getName)
                .collect(Collectors.joining(" "));
    }
}
