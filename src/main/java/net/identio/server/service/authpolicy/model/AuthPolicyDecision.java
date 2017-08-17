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
package net.identio.server.service.authpolicy.model;

import net.identio.server.model.AuthMethod;
import net.identio.server.model.AuthSession;

import java.util.HashSet;

public class AuthPolicyDecision {

	private AuthPolicyDecisionStatus status;
	private AuthSession validatedAuthSession;
	private HashSet<AuthMethod> nextAuthMethods;

	public AuthPolicyDecisionStatus getStatus() {
		return status;
	}

	public AuthPolicyDecision setStatus(AuthPolicyDecisionStatus status) {
		this.status = status;
		return this;
	}

	public AuthSession getValidatedAuthSession() {
		return validatedAuthSession;
	}

	public AuthPolicyDecision setValidatedAuthSession(AuthSession validatedAuthSession) {
		this.validatedAuthSession = validatedAuthSession;
		return this;
	}

	public HashSet<AuthMethod> getNextAuthMethods() {
		return nextAuthMethods;
	}

	public AuthPolicyDecision setNextAuthMethods(HashSet<AuthMethod> nextAuthMethods) {
		this.nextAuthMethods = nextAuthMethods;
		return this;
	}

}
