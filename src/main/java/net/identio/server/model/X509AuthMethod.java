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

public class X509AuthMethod extends AuthMethod {

	private String uidExpression;
	private String conditionExpression;
	private String security;
	private boolean apacheFix;
	private String clientCertTrust;
	private String certHeaderName;
	private String securityHeaderName;
	private String sharedSecret;
	private String proxyCertDn;
	private String proxyCertTrust;

	public X509AuthMethod() {
		this.explicit = false;
	}

	public String getUidExpression() {
		return uidExpression;
	}

	public void setUidExpression(String uidExpression) {
		this.uidExpression = uidExpression;
	}

	public String getConditionExpression() {
		return conditionExpression;
	}

	public void setConditionExpression(String conditionExpression) {
		this.conditionExpression = conditionExpression;
	}

	public String getSecurity() {
		return security;
	}

	public void setSecurity(String security) {
		this.security = security;
	}

	public boolean isApacheFix() {
		return apacheFix;
	}

	public void setApacheFix(boolean apacheFix) {
		this.apacheFix = apacheFix;
	}

	public String getClientCertTrust() {
		return clientCertTrust;
	}

	public void setClientCertTrust(String clientCertTrust) {
		this.clientCertTrust = clientCertTrust;
	}

	public String getCertHeaderName() {
		return certHeaderName;
	}

	public void setCertHeaderName(String certHeaderName) {
		this.certHeaderName = certHeaderName;
	}

	public String getSecurityHeaderName() {
		return securityHeaderName;
	}

	public void setSecurityHeaderName(String securityHeaderName) {
		this.securityHeaderName = securityHeaderName;
	}

	public String getSharedSecret() {
		return sharedSecret;
	}

	public void setSharedSecret(String sharedSecret) {
		this.sharedSecret = sharedSecret;
	}

	public String getProxyCertDn() {
		return proxyCertDn;
	}

	public void setProxyCertDn(String proxyCertDn) {
		this.proxyCertDn = proxyCertDn;
	}

	public String getProxyCertTrust() {
		return proxyCertTrust;
	}

	public void setProxyCertTrust(String proxyCertTrust) {
		this.proxyCertTrust = proxyCertTrust;
	}
}
