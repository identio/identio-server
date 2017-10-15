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
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static net.identio.server.utils.MiscUtils.nullIfEmpty;

@Configuration
@ConfigurationProperties(prefix = "authorizationConfiguration")
public class AuthorizationConfiguration implements InitializingBean {

    private static final int DEFAULT_ACCESS_TOKEN_LIFETIME = 3600;

    private HashMap<String, AuthorizationScope> scopeIndex = new HashMap<>();

    /// Configuration mapping handled by Spring Cloud config

    private List<AuthorizationScopeConfiguration> scopes = new ArrayList<>();

    public List<AuthorizationScopeConfiguration> getScopes() {
        return scopes;
    }

    public void setScopes(List<AuthorizationScopeConfiguration> scopes) {
        this.scopes = scopes;
    }

    public static class AuthorizationScopeConfiguration {

        private String name;
        private String authLevel;
        private int expirationTime;
        private HashMap<String, String> description = new HashMap<>();

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = nullIfEmpty(name);
        }

        public String getAuthLevel() {
            return authLevel;
        }

        public void setAuthLevel(String authLevel) {
            this.authLevel = nullIfEmpty(authLevel);
        }

        public int getExpirationTime() {
            return expirationTime;
        }

        public void setExpirationTime(int expirationTime) {
            this.expirationTime = expirationTime;
        }

        public HashMap<String, String> getDescription() {
            return description;
        }

        public void setDescription(HashMap<String, String> description) {
            this.description = description;
        }
    }

    /// End Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() {

        indexScopes();
    }

    private void indexScopes() {

        for (AuthorizationScopeConfiguration scopeConfig : scopes) {

            AuthorizationScope scope = new AuthorizationScope();
            scope.setName(scopeConfig.name);
            scope.setDescription(scopeConfig.description);
            scope.setExpirationTime(scopeConfig.expirationTime != 0 ? scopeConfig.expirationTime : DEFAULT_ACCESS_TOKEN_LIFETIME);

            scopeIndex.put(scopeConfig.name, scope);

        }
    }

    protected HashMap<String, AuthorizationScope> getAllScopes() {
        return scopeIndex;
    }
}
