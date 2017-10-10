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

public class ResourceOwnerCredentialsRequest {

    private String username;
    private String password;
    private String scope;

    public String getUsername() {
        return username;
    }

    public ResourceOwnerCredentialsRequest setUsername(String username) {
        this.username = username;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public ResourceOwnerCredentialsRequest setPassword(String password) {
        this.password = password;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public ResourceOwnerCredentialsRequest setScope(String scope) {
        this.scope = scope;
        return this;
    }
}
