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

public class GlobalConfiguration {

    private String publicFqdn;
    private int port;
    private boolean secure;
    private String sslKeystorePath;
    private String sslKeystorePassword;
    private String signatureKeystorePath;
    private String signatureKeystorePassword;
    private String workDirectory;
    private String staticResourcesPath;

    public String getPublicFqdn() {
        return publicFqdn;
    }

    public void setPublicFqdn(String publicFqdn) {
        this.publicFqdn = publicFqdn;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public boolean isSecure() {
        return secure;
    }

    public void setSecure(boolean secure) {
        this.secure = secure;
    }

    public String getSslKeystorePath() {
        return sslKeystorePath;
    }

    public void setSslKeystorePath(String sslKeystorePath) {
        this.sslKeystorePath = sslKeystorePath;
    }

    public String getSslKeystorePassword() {
        return sslKeystorePassword;
    }

    public void setSslKeystorePassword(String sslKeystorePassword) {
        this.sslKeystorePassword = sslKeystorePassword;
    }

    public String getSignatureKeystorePath() {
        return signatureKeystorePath;
    }

    public void setSignatureKeystorePath(String signatureKeystorePath) {
        this.signatureKeystorePath = signatureKeystorePath;
    }

    public String getSignatureKeystorePassword() {
        return signatureKeystorePassword;
    }

    public void setSignatureKeystorePassword(String signatureKeystorePassword) {
        this.signatureKeystorePassword = signatureKeystorePassword;
    }

    public String getWorkDirectory() {
        return workDirectory;
    }

    public void setWorkDirectory(String workDirectory) {
        this.workDirectory = workDirectory;
    }

    public String getStaticResourcesPath() {
        return staticResourcesPath;
    }

    public void setStaticResourcesPath(String staticResourcesPath) {
        this.staticResourcesPath = staticResourcesPath;
    }
}
