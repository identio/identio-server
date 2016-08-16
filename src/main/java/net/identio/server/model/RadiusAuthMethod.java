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

public class RadiusAuthMethod extends AuthMethod {

	private String[] radiusHost;
	private int authPort = 1812;
	private int accountPort = 1813;
	private String sharedSecret;
	private int timeout = 5000;

	public RadiusAuthMethod() {
		this.type = "radius";
	}

	public String[] getRadiusHost() {
		return radiusHost;
	}

	public void setRadiusHost(String[] radiusHost) {
		this.radiusHost = radiusHost;
	}

	public int getAuthPort() {
		return authPort;
	}

	public void setAuthPort(int authPort) {
		this.authPort = authPort;
	}

	public int getAccountPort() {
		return accountPort;
	}

	public void setAccountPort(int accountPort) {
		this.accountPort = accountPort;
	}

	public String getSharedSecret() {
		return sharedSecret;
	}

	public void setSharedSecret(String sharedSecret) {
		this.sharedSecret = sharedSecret;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

}
