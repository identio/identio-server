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

public class AuthenticationResult {

	private AuthenticationResultStatus status;
	private ErrorStatus errorStatus;
	private String challengeType;
	private String challengeValue;
	private String userId;
	private AuthMethod authMethod;
	private AuthLevel authLevel;

	public AuthenticationResultStatus getStatus() {
		return status;
	}

	public AuthenticationResult setStatus(AuthenticationResultStatus status) {
		this.status = status;
		return this;
	}

	public ErrorStatus getErrorStatus() {
		return errorStatus;
	}

	public AuthenticationResult setErrorStatus(ErrorStatus errorStatus) {
		this.errorStatus = errorStatus;
		return this;
	}

	public String getChallengeType() {
		return challengeType;
	}

	public AuthenticationResult setChallengeType(String challengeType) {
		this.challengeType = challengeType;
		return this;
	}

	public String getChallengeValue() {
		return challengeValue;
	}

	public AuthenticationResult setChallengeValue(String challengeValue) {
		this.challengeValue = challengeValue;
		return this;
	}

	public String getUserId() {
		return userId;
	}

	public AuthenticationResult setUserId(String userId) {
		this.userId = userId;
		return this;
	}

	public AuthLevel getAuthLevel() {
		return authLevel;
	}

	public AuthenticationResult setAuthLevel(AuthLevel authLevel) {
		this.authLevel = authLevel;
		return this;
	}

	public AuthMethod getAuthMethod() {
		return authMethod;
	}

	public AuthenticationResult setAuthMethod(AuthMethod authMethod) {
		this.authMethod = authMethod;
		return this;
	}
}
