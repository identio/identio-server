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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuthToken {

    public static final String BEARER_TOKEN_TYPE = "Bearer";
    public static final String REFRESH_TOKEN_TYPE = "refresh_token";

    private String value;
    private String type;

    @JsonProperty("client_id")
    private String clientId;
    private String scope;
    private String username;
    private long expiration;

    @JsonProperty("issue_at")
    private long issuedAt;

    @JsonProperty("not_before")
    private long notBefore;
    private String subject;
    private String audience;
    private String issuer;

    @JsonProperty("jwt_id")
    private String JwtId;

    private boolean active;

    public String getValue() {
        return value;
    }

    public OAuthToken setValue(String value) {
        this.value = value;
        return this;
    }

    public String getType() {
        return type;
    }

    public OAuthToken setType(String type) {
        this.type = type;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public OAuthToken setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public OAuthToken setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getUsername() {
        return username;
    }

    public OAuthToken setUsername(String username) {
        this.username = username;
        return this;
    }

    public long getExpiration() {
        return expiration;
    }

    public OAuthToken setExpiration(long expiration) {
        this.expiration = expiration;
        return this;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public OAuthToken setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public long getNotBefore() {
        return notBefore;
    }

    public OAuthToken setNotBefore(long notBefore) {
        this.notBefore = notBefore;
        return this;
    }

    public String getSubject() {
        return subject;
    }

    public OAuthToken setSubject(String subject) {
        this.subject = subject;
        return this;
    }

    public String getAudience() {
        return audience;
    }

    public OAuthToken setAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public String getIssuer() {
        return issuer;
    }

    public OAuthToken setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String getJwtId() {
        return JwtId;
    }

    public OAuthToken setJwtId(String jwtId) {
        JwtId = jwtId;
        return this;
    }

    public boolean isActive() {
        return active;
    }

    public OAuthToken setActive(boolean active) {
        this.active = active;
        return this;
    }
}
