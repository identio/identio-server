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
package net.identio.server.service.authentication.radius;

import net.identio.server.model.AuthMethod;

import java.util.List;

public class RadiusAuthMethod extends AuthMethod {

    private List<String> radiusHost;
    private int authPort = 1812;
    private int accountPort = 1813;
    private String sharedSecret;
    private int timeout = 5000;

    public List<String> getRadiusHost() {
        return radiusHost;
    }

    public RadiusAuthMethod setRadiusHost(List<String> radiusHost) {
        this.radiusHost = radiusHost;
        return this;
    }

    public int getAuthPort() {
        return authPort;
    }

    public RadiusAuthMethod setAuthPort(int authPort) {
        this.authPort = authPort;
        return this;
    }

    public int getAccountPort() {
        return accountPort;
    }

    public RadiusAuthMethod setAccountPort(int accountPort) {
        this.accountPort = accountPort;
        return this;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public RadiusAuthMethod setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
        return this;
    }

    public int getTimeout() {
        return timeout;
    }

    public RadiusAuthMethod setTimeout(int timeout) {
        this.timeout = timeout;
        return this;
    }

}
