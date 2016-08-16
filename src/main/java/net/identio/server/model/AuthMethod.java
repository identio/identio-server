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

public abstract class AuthMethod {

	protected boolean explicit = true;

	private String name;
	private String logoFileName;
	private AuthLevel authLevel;
	private StepUpAuthMethod stepUpAuthentication;
	protected String type;

	public boolean isExplicit() {
		return explicit;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getLogoFileName() {
		return logoFileName;
	}

	public void setLogoFileName(String logoFileName) {
		this.logoFileName = logoFileName;
	}

	public AuthLevel getAuthLevel() {
		return authLevel;
	}

	public void setAuthLevel(AuthLevel authLevel) {
		this.authLevel = authLevel;
	}

	public StepUpAuthMethod getStepUpAuthentication() {
		return stepUpAuthentication;
	}

	public void setStepUpAuthentication(StepUpAuthMethod stepUpAuthentication) {
		this.stepUpAuthentication = stepUpAuthentication;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	@Override
	public boolean equals(Object obj) {
		return obj != null && obj instanceof AuthMethod && this.name.equals(((AuthMethod) obj).name);
	}
}
