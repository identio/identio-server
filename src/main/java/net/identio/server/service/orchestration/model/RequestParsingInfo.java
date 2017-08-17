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
package net.identio.server.service.orchestration.model;

import net.identio.server.model.AuthLevel;
import net.identio.server.model.AuthorizationScope;
import net.identio.server.model.ProtocolType;

import java.util.List;

public class RequestParsingInfo {

    private RequestParsingStatus status;
    private String errorStatus;
    private String requestId;
    private ProtocolType protocolType;
    private String sourceApplicationName;
    private boolean forceAuthentication;
    private String authLevelComparison;
    private List<AuthLevel> requestedAuthLevels;
    private String relayState;
    private String responseUrl;
    private List<AuthorizationScope> requestedScopes;
    private String responseType;

    public RequestParsingStatus getStatus() {
        return status;
    }

    public RequestParsingInfo setStatus(RequestParsingStatus status) {
        this.status = status;
        return this;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public RequestParsingInfo setErrorStatus(String errorStatus) {
        this.errorStatus = errorStatus;
        return this;
    }

    public String getRequestId() {
        return requestId;
    }

    public RequestParsingInfo setRequestId(String requestId) {
        this.requestId = requestId;
        return this;
    }

    public ProtocolType getProtocolType() {
        return protocolType;
    }

    public RequestParsingInfo setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
        return this;
    }

    public String getSourceApplicationName() {
        return sourceApplicationName;
    }

    public RequestParsingInfo setSourceApplicationName(String sourceApplicationName) {
        this.sourceApplicationName = sourceApplicationName;
        return this;
    }

    public boolean isForceAuthentication() {
        return forceAuthentication;
    }

    public RequestParsingInfo setForceAuthentication(boolean forceAuthentication) {
        this.forceAuthentication = forceAuthentication;
        return this;
    }

    public String getAuthLevelComparison() {
        return authLevelComparison;
    }

    public RequestParsingInfo setAuthLevelComparison(String authLevelComparison) {
        this.authLevelComparison = authLevelComparison;
        return this;
    }

    public List<AuthLevel> getRequestedAuthLevels() {
        return requestedAuthLevels;
    }

    public RequestParsingInfo setRequestedAuthLevels(List<AuthLevel> requestedAuthLevels) {
        this.requestedAuthLevels = requestedAuthLevels;
        return this;
    }

    public String getRelayState() {
        return relayState;
    }

    public RequestParsingInfo setRelayState(String relayState) {
        this.relayState = relayState;
        return this;
    }

    public String getResponseUrl() {
        return responseUrl;
    }

    public RequestParsingInfo setResponseUrl(String responseUrl) {
        this.responseUrl = responseUrl;
        return this;
    }

    public List<AuthorizationScope> getRequestedScopes() {
        return requestedScopes;
    }

    public RequestParsingInfo setRequestedScopes(List<AuthorizationScope> requestedScopes) {
        this.requestedScopes = requestedScopes;
        return this;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }
}
