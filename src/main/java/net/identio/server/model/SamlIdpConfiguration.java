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

public class SamlIdpConfiguration {

	private String organizationName;
	private String organizationDisplayName;
	private String organizationUrl;
	private String contactPersonSurname;
	private String contactPersonEmail;
	private String keystore;
	private String keystorePassword;
	private boolean allowUnsecureRequests;
	private boolean certificateCheckEnabled;
	private int tokenValidityLength;
	private int allowedTimeOffset;
	private String spMetadataDirectory;

	public String getKeystore() {
		return keystore;
	}

	public void setKeystore(String keystore) {
		this.keystore = keystore;
	}

	public String getKeystorePassword() {
		return keystorePassword;
	}

	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}

	public boolean isCertificateCheckEnabled() {
		return certificateCheckEnabled;
	}

	public void setCertificateCheckEnabled(boolean certificateCheckEnabled) {
		this.certificateCheckEnabled = certificateCheckEnabled;
	}

	public int getTokenValidityLength() {
		return tokenValidityLength;
	}

	public void setTokenValidityLength(int tokenValidityLength) {
		this.tokenValidityLength = tokenValidityLength;
	}

	public int getAllowedTimeOffset() {
		return allowedTimeOffset;
	}

	public void setAllowedTimeOffset(int allowedTimeOffset) {
		this.allowedTimeOffset = allowedTimeOffset;
	}

	public String getSpMetadataDirectory() {
		return spMetadataDirectory;
	}

	public void setSpMetadataDirectory(String spDirectory) {
		this.spMetadataDirectory = spDirectory;
	}

	public String getOrganizationName() {
		return organizationName;
	}

	public void setOrganizationName(String organizationName) {
		this.organizationName = organizationName;
	}

	public String getOrganizationDisplayName() {
		return organizationDisplayName;
	}

	public void setOrganizationDisplayName(String organizationDisplayName) {
		this.organizationDisplayName = organizationDisplayName;
	}

	public String getOrganizationUrl() {
		return organizationUrl;
	}

	public void setOrganizationUrl(String organizationUrl) {
		this.organizationUrl = organizationUrl;
	}

	public String getContactPersonSurname() {
		return contactPersonSurname;
	}

	public void setContactPersonSurname(String contactPersonSurname) {
		this.contactPersonSurname = contactPersonSurname;
	}

	public String getContactPersonEmail() {
		return contactPersonEmail;
	}

	public void setContactPersonEmail(String contactPersonEmail) {
		this.contactPersonEmail = contactPersonEmail;
	}

	public boolean isAllowUnsecureRequests() {
		return allowUnsecureRequests;
	}

	public void setAllowUnsecureRequests(boolean allowUnsecureRequests) {
		this.allowUnsecureRequests = allowUnsecureRequests;
	}
}
