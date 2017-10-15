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
package net.identio.server.service.authentication.x509;

import net.identio.server.model.AuthMethod;

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

    public String getUidExpression() {
        return uidExpression;
    }

    public X509AuthMethod setUidExpression(String uidExpression) {
        this.uidExpression = uidExpression;
        return this;
    }

    public String getConditionExpression() {
        return conditionExpression;
    }

    public X509AuthMethod setConditionExpression(String conditionExpression) {
        this.conditionExpression = conditionExpression;
        return this;
    }

    public String getSecurity() {
        return security;
    }

    public X509AuthMethod setSecurity(String security) {
        this.security = security;
        return this;
    }

    public boolean isApacheFix() {
        return apacheFix;
    }

    public X509AuthMethod setApacheFix(boolean apacheFix) {
        this.apacheFix = apacheFix;
        return this;
    }

    public String getClientCertTrust() {
        return clientCertTrust;
    }

    public X509AuthMethod setClientCertTrust(String clientCertTrust) {
        this.clientCertTrust = clientCertTrust;
        return this;
    }

    public String getCertHeaderName() {
        return certHeaderName;
    }

    public X509AuthMethod setCertHeaderName(String certHeaderName) {
        this.certHeaderName = certHeaderName;
        return this;
    }

    public String getSecurityHeaderName() {
        return securityHeaderName;
    }

    public X509AuthMethod setSecurityHeaderName(String securityHeaderName) {
        this.securityHeaderName = securityHeaderName;
        return this;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public X509AuthMethod setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
        return this;
    }

    public String getProxyCertDn() {
        return proxyCertDn;
    }

    public X509AuthMethod setProxyCertDn(String proxyCertDn) {
        this.proxyCertDn = proxyCertDn;
        return this;
    }

    public String getProxyCertTrust() {
        return proxyCertTrust;
    }

    public X509AuthMethod setProxyCertTrust(String proxyCertTrust) {
        this.proxyCertTrust = proxyCertTrust;
        return this;
    }
}
