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

package net.identio.server.boot;

import net.identio.server.utils.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import static net.identio.server.utils.MiscUtils.nullIfEmpty;

@Configuration
@ConfigurationProperties(prefix = "global")
public class GlobalConfiguration implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalConfiguration.class);

    private static final String DEFAULT_SSL_KEYSTORE_PASSWORD = "password";
    private static final String DEFAULT_SSL_KEYSTORE_PATH = "config/ssl-certificate.p12";
    private static final int DEFAULT_HTTP_PORT = 10080;
    private static final int DEFAULT_HTTPS_PORT = 10443;
    private static final String DEFAULT_KEYSTORE_PASSWORD = "password";
    private static final String DEFAULT_KEYSTORE_PATH = "config/default-sign-certificate.p12";
    private static final String DEFAULT_STATIC_RESOURCE_PATH = "ui/";

    /// Configuration mapping handled by Spring Cloud config

    private String basePublicUrl;
    private int port;
    private boolean secure;
    private String sslKeystorePath;
    private String sslKeystorePassword;
    private String signatureKeystorePath;
    private String signatureKeystorePassword;
    private String staticResourcesPath;

    public String getBasePublicUrl() {
        return basePublicUrl;
    }

    public void setBasePublicUrl(String basePublicUrl) {
        this.basePublicUrl = nullIfEmpty(basePublicUrl);
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
        this.sslKeystorePath = nullIfEmpty(sslKeystorePath);
    }

    public String getSslKeystorePassword() {
        return sslKeystorePassword;
    }

    public void setSslKeystorePassword(String sslKeystorePassword) {
        this.sslKeystorePassword = nullIfEmpty(sslKeystorePassword);
    }

    public String getSignatureKeystorePath() {
        return signatureKeystorePath;
    }

    public void setSignatureKeystorePath(String signatureKeystorePath) {
        this.signatureKeystorePath = nullIfEmpty(signatureKeystorePath);
    }

    public String getSignatureKeystorePassword() {
        return signatureKeystorePassword;
    }

    public void setSignatureKeystorePassword(String signatureKeystorePassword) {
        this.signatureKeystorePassword = nullIfEmpty(signatureKeystorePassword);
    }

    public String getStaticResourcesPath() {
        return staticResourcesPath;
    }

    public void setStaticResourcesPath(String staticResourcesPath) {
        this.staticResourcesPath = nullIfEmpty(staticResourcesPath);
    }

    /// End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() throws Exception {

        setDefaultValues();

        verifyValues();
    }

    private void setDefaultValues() {

        if (secure) {
            sslKeystorePassword = sslKeystorePassword != null ? sslKeystorePassword : DEFAULT_SSL_KEYSTORE_PASSWORD;
            sslKeystorePath = sslKeystorePath != null ? sslKeystorePath : DEFAULT_SSL_KEYSTORE_PATH;
        }

        if (port == 0) port = secure ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT;

        signatureKeystorePassword = signatureKeystorePassword != null ? signatureKeystorePassword : DEFAULT_KEYSTORE_PASSWORD;
        signatureKeystorePath = signatureKeystorePath != null ? signatureKeystorePath : DEFAULT_KEYSTORE_PATH;

        staticResourcesPath = staticResourcesPath != null ? staticResourcesPath : DEFAULT_STATIC_RESOURCE_PATH;
    }

    private void verifyValues() {

        if (basePublicUrl == null)
            IdentioServerApplication.quitOnConfigurationError(LOG,
                    "Global configuration error: \"global > basePublicUrl\" property must be set");

        if (secure && !FileUtils.fileExists(sslKeystorePath))
            IdentioServerApplication.quitOnConfigurationError(LOG,
                    "Global configuration error: SSL Keystore file " + sslKeystorePath + " doesn't exist");

        if (!FileUtils.fileExists(signatureKeystorePath))
            IdentioServerApplication.quitOnConfigurationError(LOG,
                    "Global configuration error: Signature Keystore file " + sslKeystorePath + " doesn't exist");

        if (!FileUtils.fileExists(staticResourcesPath))
            IdentioServerApplication.quitOnConfigurationError(LOG,
                    "Global configuration error: Static resources directory " + staticResourcesPath + " doesn't exist");
    }
}
