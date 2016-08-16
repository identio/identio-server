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

import java.util.HashSet;

public class AuthPolicyDecision {

	private State nextState;
	private AuthSession validatedAuthSession;
	private HashSet<AuthMethod> nextAuthMethods;

	public AuthPolicyDecision(State nextState, AuthSession validatedAuthSession, HashSet<AuthMethod> nextAuthMethods) {
		this.nextState = nextState;
		this.validatedAuthSession = validatedAuthSession;
		this.setNextAuthMethods(nextAuthMethods);
	}

	public State getNextState() {
		return nextState;
	}

	public void setNextState(State nextState) {
		this.nextState = nextState;
	}

	public AuthSession getValidatedAuthSession() {
		return validatedAuthSession;
	}

	public void setValidatedAuthSession(AuthSession validatedAuthSession) {
		this.validatedAuthSession = validatedAuthSession;
	}

	public HashSet<AuthMethod> getNextAuthMethods() {
		return nextAuthMethods;
	}

	public void setNextAuthMethods(HashSet<AuthMethod> nextAuthMethods) {
		this.nextAuthMethods = nextAuthMethods;
	}

}
