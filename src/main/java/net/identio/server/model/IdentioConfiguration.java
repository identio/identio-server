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

public class IdentioConfiguration {

	private GlobalConfiguration globalConfiguration = new GlobalConfiguration();
	private SamlIdpConfiguration samlIdpConfiguration = new SamlIdpConfiguration();
	private SessionConfiguration sessionConfiguration = new SessionConfiguration();
	private AuthPolicyConfiguration authPolicyConfiguration = new AuthPolicyConfiguration();
	private AuthMethodConfiguration authMethodConfiguration = new AuthMethodConfiguration();
	private OAuthServerConfiguration oAuthServerConfiguration = new OAuthServerConfiguration();
	private AuthorizationConfiguration authorizationConfiguration = new AuthorizationConfiguration();

	public GlobalConfiguration getGlobalConfiguration() {
		return globalConfiguration;
	}

	public void setGlobalConfiguration(GlobalConfiguration globalConfiguration) {
		this.globalConfiguration = globalConfiguration;
	}

	public SamlIdpConfiguration getSamlIdpConfiguration() {
		return samlIdpConfiguration;
	}

	public void setSamlIdpConfiguration(SamlIdpConfiguration samlIdpConfiguration) {
		this.samlIdpConfiguration = samlIdpConfiguration;
	}

	public SessionConfiguration getSessionConfiguration() {
		return sessionConfiguration;
	}

	public void setSessionConfiguration(SessionConfiguration sessionConfiguration) {
		this.sessionConfiguration = sessionConfiguration;
	}

	public AuthPolicyConfiguration getAuthPolicyConfiguration() {
		return authPolicyConfiguration;
	}

	public void setAuthPolicyConfiguration(AuthPolicyConfiguration authPolicyConfiguration) {
		this.authPolicyConfiguration = authPolicyConfiguration;
	}

	public AuthMethodConfiguration getAuthMethodConfiguration() {
		return authMethodConfiguration;
	}

	public void setAuthMethodConfiguration(AuthMethodConfiguration authMethodConfiguration) {
		this.authMethodConfiguration = authMethodConfiguration;
	}

	public OAuthServerConfiguration getoAuthServerConfiguration() {
		return oAuthServerConfiguration;
	}

	public void setoAuthServerConfiguration(OAuthServerConfiguration oAuthServerConfiguration) {
		this.oAuthServerConfiguration = oAuthServerConfiguration;
	}

	public AuthorizationConfiguration getAuthorizationConfiguration() {
		return authorizationConfiguration;
	}

	public void setAuthorizationConfiguration(AuthorizationConfiguration authorizationConfiguration) {
		this.authorizationConfiguration = authorizationConfiguration;
	}
}
