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
package net.identio.server.service.authentication.ldap;

import net.identio.server.model.AuthMethod;

import java.util.List;

public class LdapAuthMethod extends AuthMethod {

    private List<String> ldapUrl;
    private String proxyUser;
    private String proxyPassword;
    private String baseDn;
    private String userSearchFilter;
    private String trustCert;
    private LdapAuthenticationProviderConfiguration.LdapPoolConfig poolConfig;

    public LdapAuthMethod() {
        this.type = "ldap";
    }

    public List<String> getLdapUrl() {
        return ldapUrl;
    }

    public LdapAuthMethod setLdapUrl(List<String> ldapUrl) {
        this.ldapUrl = ldapUrl;
        return this;
    }

    public String getProxyUser() {
        return proxyUser;
    }

    public LdapAuthMethod setProxyUser(String proxyUser) {
        this.proxyUser = proxyUser;
        return this;
    }

    public String getProxyPassword() {
        return proxyPassword;
    }

    public LdapAuthMethod setProxyPassword(String proxyPassword) {
        this.proxyPassword = proxyPassword;
        return this;
    }

    public String getBaseDn() {
        return baseDn;
    }

    public LdapAuthMethod setBaseDn(String baseDn) {
        this.baseDn = baseDn;
        return this;
    }

    public String getUserSearchFilter() {
        return userSearchFilter;
    }

    public LdapAuthMethod setUserSearchFilter(String userSearchFilter) {
        this.userSearchFilter = userSearchFilter;
        return this;
    }

    public String getTrustCert() {
        return trustCert;
    }

    public LdapAuthMethod setTrustCert(String trustCert) {
        this.trustCert = trustCert;
        return this;
    }

    public LdapAuthenticationProviderConfiguration.LdapPoolConfig getPoolConfig() {
        return poolConfig;
    }

    public LdapAuthMethod setPoolConfig(LdapAuthenticationProviderConfiguration.LdapPoolConfig poolConfig) {
        this.poolConfig = poolConfig;
        return this;
    }

}
