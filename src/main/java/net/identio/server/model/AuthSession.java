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

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class AuthSession {

	private DateTime authInstant;
	private AuthMethod authMethod;
	private StepUpAuthMethod stepUpAuthMethod;
	private AuthLevel authLevel;

	public AuthSession(AuthMethod authMethod, StepUpAuthMethod stepUpAuthMethod, AuthLevel authLevel) {
		this.authInstant = new DateTime(DateTimeZone.UTC);
		this.authMethod = authMethod;
		this.stepUpAuthMethod = stepUpAuthMethod;
		this.authLevel = authLevel;
	}

	public DateTime getAuthInstant() {
		return authInstant;
	}

	public void setAuthInstant(DateTime authInstant) {
		this.authInstant = authInstant;
	}

	public AuthMethod getAuthMethod() {
		return authMethod;
	}

	public void setAuthMethod(AuthMethod authMethod) {
		this.authMethod = authMethod;
	}

	public StepUpAuthMethod getStepUpAuthMethod() {
		return stepUpAuthMethod;
	}

	public void setStepUpAuthMethod(StepUpAuthMethod stepUpAuthMethod) {
		this.stepUpAuthMethod = stepUpAuthMethod;
	}

	public AuthLevel getAuthLevel() {
		return authLevel;
	}

	public void setAuthLevel(AuthLevel authLevel) {
		this.authLevel = authLevel;
	}
}
