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
package net.identio.server.service.oauth.model;

import java.util.List;

public class Client {

    private String name;
    private String clientId;
    private String clientSecret;
    private List<String> allowedScopes;
    private List<String> responseUri;
    private List<String> allowedGrants;
    private boolean consentNeeded;
    private String resourceOwnerAuthMethod;
    private boolean forcePkce;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<String> getAllowedScopes() {
        return allowedScopes;
    }

    public void setAllowedScopes(List<String> allowedScopes) {
        this.allowedScopes = allowedScopes;
    }

    public List<String> getResponseUri() {
        return responseUri;
    }

    public void setResponseUri(List<String> responseUri) {
        this.responseUri = responseUri;
    }

    public List<String> getAllowedGrants() {
        return allowedGrants;
    }

    public void setAllowedGrants(List<String> allowedGrants) {
        this.allowedGrants = allowedGrants;
    }

    public boolean isConsentNeeded() {
        return consentNeeded;
    }

    public void setConsentNeeded(boolean consentNeeded) {
        this.consentNeeded = consentNeeded;
    }

    public String getResourceOwnerAuthMethod() {
        return resourceOwnerAuthMethod;
    }

    public void setResourceOwnerAuthMethod(String resourceOwnerAuthMethod) {
        this.resourceOwnerAuthMethod = resourceOwnerAuthMethod;
    }

    public boolean isForcePkce() {
        return forcePkce;
    }

    public void setForcePkce(boolean forcePkce) {
        this.forcePkce = forcePkce;
    }
}
