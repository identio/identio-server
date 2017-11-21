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
package net.identio.server.service.authentication.model;

import java.security.cert.X509Certificate;

public class X509Authentication implements Authentication {

    private X509Certificate[] clientAuthCert;
    private String userCert;
    private String sharedSecret;

    public X509Certificate[] getClientAuthCert() {
        return clientAuthCert;
    }

    public void setClientAuthCert(X509Certificate[] certificates) {
        this.clientAuthCert = certificates;
    }

    public String getUserCert() {
        return userCert;
    }

    public void setUserCert(String userCert) {
        this.userCert = userCert;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public X509Authentication(X509Certificate[] clientAuthCert,
                              String userCert, String sharedSecret) {
        this.clientAuthCert = clientAuthCert;
        this.userCert = userCert;
        this.sharedSecret = sharedSecret;
    }
}
