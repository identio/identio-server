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

public class SamlAuthMethod extends AuthMethod {

	private String metadata;
	private boolean certificateCheckEnabled = false;
	private SamlAuthMap samlAuthMap;

	public SamlAuthMethod() {
		this.type = "saml";
	}

	public String getMetadata() {
		return metadata;
	}

	public void setMetadata(String metadata) {
		this.metadata = metadata;
	}

	public boolean isCertificateCheckEnabled() {
		return certificateCheckEnabled;
	}

	public void setCertificateCheckEnabled(boolean certificateCheckEnabled) {
		this.certificateCheckEnabled = certificateCheckEnabled;
	}

	public SamlAuthMap getSamlAuthMap() {
		return samlAuthMap;
	}

	public void setSamlAuthMap(SamlAuthMap samlAuthMap) {
		this.samlAuthMap = samlAuthMap;
	}
}
