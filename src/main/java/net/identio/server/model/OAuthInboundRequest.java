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

package net.identio.server.model;

public class OAuthInboundRequest implements InboundRequest {

    private String clientId;
    private String responseType;
    private String redirectUri;
    private String scope;
    private String state;
    private String codeChallenge;
    private String codeChallengeMethod;

    public String getClientId() {
        return clientId;
    }

    public OAuthInboundRequest setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getResponseType() {
        return responseType;
    }

    public OAuthInboundRequest setResponseType(String responseType) {
        this.responseType = responseType;
        return this;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public OAuthInboundRequest setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public OAuthInboundRequest setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public String getState() {
        return state;
    }

    public OAuthInboundRequest setState(String state) {
        this.state = state;
        return this;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public OAuthInboundRequest setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
        return this;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public OAuthInboundRequest setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
        return this;
    }
}
