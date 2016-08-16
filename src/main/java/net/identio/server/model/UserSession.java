/*
 This file is part of Ident.io

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

import java.util.ArrayList;
import java.util.HashSet;

public class UserSession {

	private String id;
	private String userId;
	private ArrayList<AuthSession> authSessions = new ArrayList<>();
	private HashSet<AuthMethod> validatedAuthMethods = new HashSet<>();

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public ArrayList<AuthSession> getAuthSessions() {
		return authSessions;
	}

	public void setAuthSessions(ArrayList<AuthSession> authSessions) {
		this.authSessions = authSessions;
	}

	public HashSet<AuthMethod> getValidatedAuthMethods() {
		return validatedAuthMethods;
	}

	public void setValidatedAuthMethods(HashSet<AuthMethod> validatedAuthMethods) {
		this.validatedAuthMethods = validatedAuthMethods;
	}

	public AuthSession addAuthSession(String userId, AuthMethod authMethod, StepUpAuthMethod stepUpAuthMethod,
			AuthLevel authLevel) {
		AuthSession authSession = new AuthSession(authMethod, stepUpAuthMethod, authLevel);
		this.userId = userId;
		this.authSessions.add(authSession);
		this.validatedAuthMethods.add(authMethod);

		return authSession;
	}
}
