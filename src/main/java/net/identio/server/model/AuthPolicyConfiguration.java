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

public class AuthPolicyConfiguration {

	private List<AuthLevel> authLevels;
	private AppAuthLevel defaultAuthLevel;
	private List<AppAuthLevel> applicationSpecificAuthLevel;

	public List<AuthLevel> getAuthLevels() {
		return authLevels;
	}

	public void setAuthLevels(List<AuthLevel> authLevels) {
		this.authLevels = authLevels;
	}

	public AppAuthLevel getDefaultAuthLevel() {
		return defaultAuthLevel;
	}

	public void setDefaultAuthLevel(AppAuthLevel defaultAuthLevel) {
		this.defaultAuthLevel = defaultAuthLevel;
	}

	public List<AppAuthLevel> getApplicationSpecificAuthLevel() {
		return applicationSpecificAuthLevel;
	}

	public void setApplicationSpecificAuthLevel(List<AppAuthLevel> applicationSpecificAuthLevel) {
		this.applicationSpecificAuthLevel = applicationSpecificAuthLevel;
	}

}
