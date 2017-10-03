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

public class RefreshToken {

    private String value;
    private String clientId;
    private int expiresIn;
    private String scope;
    private String userId;

    public String getValue() {
        return value;
    }

    public RefreshToken setValue(String value) {
        this.value = value;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public RefreshToken setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public RefreshToken setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public RefreshToken setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public String getUserId() {
        return userId;
    }

    public RefreshToken setUserId(String userId) {
        this.userId = userId;
        return this;
    }
}
