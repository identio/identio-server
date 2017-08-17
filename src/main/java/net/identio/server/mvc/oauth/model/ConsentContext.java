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

package net.identio.server.mvc.oauth.model;

import net.identio.server.model.AuthorizationScope;

import java.util.List;

public class ConsentContext {

    private String audience;
    private String audienceLogo;
    private List<AuthorizationScope> requestedScopes;

    public String getAudience() {
        return audience;
    }

    public ConsentContext setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public String getAudienceLogo() {
        return audienceLogo;
    }

    public ConsentContext setAudienceLogo(String audienceLogo) {
        this.audienceLogo = audienceLogo;
        return this;
    }

    public List<AuthorizationScope> getRequestedScopes() {
        return requestedScopes;
    }

    public ConsentContext setRequestedScopes(List<AuthorizationScope> requestedScopes) {
        this.requestedScopes = requestedScopes;
        return this;
    }
}
