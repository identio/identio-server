/*
 This file is part of Ident.io.

 Ident.io - A flexible authentication server
 Copyright (C) Loeiz TANGUY

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.identio.server.model;

import java.util.List;

public class AuthRequestValidationResult {

	private boolean success;
	private ErrorStatus errorStatus;
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
	
	public boolean isSuccess() {
		return success;
	}

	public ErrorStatus getErrorStatus() {
		return errorStatus;
	}

	public AuthRequestValidationResult setErrorStatus(ErrorStatus errorStatus) {
		this.errorStatus = errorStatus;
		return this;
	}

	public AuthRequestValidationResult setSuccess(boolean success) {
		this.success = success;
		return this;
	}

	public String getRequestId() {
		return requestId;
	}

	public AuthRequestValidationResult setRequestId(String requestId) {
		this.requestId = requestId;
		return this;
	}

	public ProtocolType getProtocolType() {
		return protocolType;
	}

	public AuthRequestValidationResult setProtocolType(ProtocolType protocolType) {
		this.protocolType = protocolType;
		return this;
	}

	public String getSourceApplicationName() {
		return sourceApplicationName;
	}

	public AuthRequestValidationResult setSourceApplicationName(String sourceApplicationName) {
		this.sourceApplicationName = sourceApplicationName;
		return this;
	}

	public boolean isForceAuthentication() {
		return forceAuthentication;
	}

	public AuthRequestValidationResult setForceAuthentication(boolean forceAuthentication) {
		this.forceAuthentication = forceAuthentication;
		return this;
	}

	public String getAuthLevelComparison() {
		return authLevelComparison;
	}

	public AuthRequestValidationResult setAuthLevelComparison(String authLevelComparison) {
		this.authLevelComparison = authLevelComparison;
		return this;
	}

	public List<AuthLevel> getRequestedAuthLevels() {
		return requestedAuthLevels;
	}

	public AuthRequestValidationResult setRequestedAuthLevels(List<AuthLevel> requestedAuthLevels) {
		this.requestedAuthLevels = requestedAuthLevels;
		return this;
	}

	public String getRelayState() {
		return relayState;
	}

	public AuthRequestValidationResult setRelayState(String relayState) {
		this.relayState = relayState;
		return this;
	}

	public String getResponseUrl() {
		return responseUrl;
	}

	public AuthRequestValidationResult setResponseUrl(String responseUrl) {
		this.responseUrl = responseUrl;
		return this;
	}

	public List<AuthorizationScope> getRequestedScopes() {
		return requestedScopes;
	}

	public AuthRequestValidationResult setRequestedScopes(List<AuthorizationScope> requestedScopes) {
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
