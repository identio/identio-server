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
package net.identio.server.model;

import java.util.ArrayList;
import java.util.List;

public class AuthMethodConfiguration {

    private List<LdapAuthMethod> ldapAuthMethods;
    private List<X509AuthMethod> x509AuthMethods;
    private List<RadiusAuthMethod> radiusAuthMethods;
    private List<SamlAuthMethod> samlAuthMethods;
    private List<LocalAuthMethod> localAuthMethods;
    private List<AuthMethod> authMethods;

    public List<LdapAuthMethod> getLdapAuthMethods() {
        return ldapAuthMethods;
    }

    public void setLdapAuthMethods(List<LdapAuthMethod> ldapAuthMethods) {
        this.ldapAuthMethods = ldapAuthMethods;
    }

    public List<X509AuthMethod> getX509AuthMethods() {
        return x509AuthMethods;
    }

    public void setX509AuthMethods(List<X509AuthMethod> x509AuthMethods) {
        this.x509AuthMethods = x509AuthMethods;
    }

    public List<RadiusAuthMethod> getRadiusAuthMethods() {
        return radiusAuthMethods;
    }

    public void setRadiusAuthMethods(List<RadiusAuthMethod> radiusAuthMethods) {
        this.radiusAuthMethods = radiusAuthMethods;
    }

    public List<SamlAuthMethod> getSamlAuthMethods() {
        return samlAuthMethods;
    }

    public void setSamlAuthMethods(List<SamlAuthMethod> samlAuthMethods) {
        this.samlAuthMethods = samlAuthMethods;
    }

    public List<LocalAuthMethod> getLocalAuthMethods() {
        return localAuthMethods;
    }

    public void setLocalAuthMethods(List<LocalAuthMethod> localAuthMethods) {
        this.localAuthMethods = localAuthMethods;
    }

    public List<AuthMethod> getAuthMethods() {

        if (authMethods == null) {
            authMethods = new ArrayList<>();

            if (ldapAuthMethods != null)
                authMethods.addAll(ldapAuthMethods);
            if (x509AuthMethods != null)
                authMethods.addAll(x509AuthMethods);
            if (radiusAuthMethods != null)
                authMethods.addAll(radiusAuthMethods);
            if (samlAuthMethods != null)
                authMethods.addAll(samlAuthMethods);
            if (localAuthMethods != null)
                authMethods.addAll(localAuthMethods);
        }

        return authMethods;
    }

}
