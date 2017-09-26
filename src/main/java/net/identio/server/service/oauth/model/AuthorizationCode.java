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

public class AuthorizationCode {

    private String code;
    private String clientId;
    private String redirectUrl;
    private long expirationTime;
    private String scope;
    private String userId;

    public String getCode() {
        return code;
    }

    public AuthorizationCode setCode(String code) {
        this.code = code;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public AuthorizationCode setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public AuthorizationCode setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
        return this;
    }

    public long getExpirationTime() {
        return expirationTime;
    }

    public AuthorizationCode setExpirationTime(long expirationTime) {
        this.expirationTime = expirationTime;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public AuthorizationCode setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public String getUserId() {
        return userId;
    }

    public AuthorizationCode setUserId(String userId) {
        this.userId = userId;
        return this;
    }
}

