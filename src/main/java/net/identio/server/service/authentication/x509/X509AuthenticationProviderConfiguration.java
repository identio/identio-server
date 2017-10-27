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

import net.identio.server.boot.GlobalConstants;
import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.utils.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

import static net.identio.server.utils.MiscUtils.nullIfEmpty;

@Configuration
@ConfigurationProperties(prefix = "authMethods")
public class X509AuthenticationProviderConfiguration implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(X509AuthenticationProviderConfiguration.class);

    private List<X509AuthMethod> authMethods = new ArrayList<>();

    @Autowired
    private AuthPolicyService authPolicyService;

    /// Configuration mapping handled by Spring Cloud config

    private List<X509AuthMethodConfiguration> x509AuthMethods = new ArrayList<>();

    public List<X509AuthMethodConfiguration> getX509AuthMethods() {
        return x509AuthMethods;
    }

    public void setX509AuthMethods(List<X509AuthMethodConfiguration> x509AuthMethods) {
        this.x509AuthMethods = x509AuthMethods;
    }

    public static class X509AuthMethodConfiguration {

        private String name;
        private String logoFileName;
        private String authLevel;
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

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = nullIfEmpty(name);
        }

        public String getLogoFileName() {
            return logoFileName;
        }

        public void setLogoFileName(String logoFileName) {
            this.logoFileName = nullIfEmpty(logoFileName);
        }

        public String getAuthLevel() {
            return authLevel;
        }

        public void setAuthLevel(String authLevel) {
            this.authLevel = nullIfEmpty(authLevel);
        }

        public String getUidExpression() {
            return uidExpression;
        }

        public void setUidExpression(String uidExpression) {
            this.uidExpression = nullIfEmpty(uidExpression);
        }

        public String getConditionExpression() {
            return conditionExpression;
        }

        public void setConditionExpression(String conditionExpression) {
            this.conditionExpression = nullIfEmpty(conditionExpression);
        }

        public String getSecurity() {
            return security;
        }

        public void setSecurity(String security) {
            this.security = nullIfEmpty(security);
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
            this.clientCertTrust = nullIfEmpty(clientCertTrust);
        }

        public String getCertHeaderName() {
            return certHeaderName;
        }

        public void setCertHeaderName(String certHeaderName) {
            this.certHeaderName = nullIfEmpty(certHeaderName);
        }

        public String getSecurityHeaderName() {
            return securityHeaderName;
        }

        public void setSecurityHeaderName(String securityHeaderName) {
            this.securityHeaderName = nullIfEmpty(securityHeaderName);
        }

        public String getSharedSecret() {
            return sharedSecret;
        }

        public void setSharedSecret(String sharedSecret) {
            this.sharedSecret = nullIfEmpty(sharedSecret);
        }

        public String getProxyCertDn() {
            return proxyCertDn;
        }

        public void setProxyCertDn(String proxyCertDn) {
            this.proxyCertDn = nullIfEmpty(proxyCertDn);
        }

        public String getProxyCertTrust() {
            return proxyCertTrust;
        }

        public void setProxyCertTrust(String proxyCertTrust) {
            this.proxyCertTrust = nullIfEmpty(proxyCertTrust);
        }
    }

    /// End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() {

        indexAuthMethods();
        verifyValues();
    }

    private void indexAuthMethods() {

        for (X509AuthMethodConfiguration config : x509AuthMethods) {

            X509AuthMethod authMethod = new X509AuthMethod();

            try {

                authMethod.setName(config.name);
                authMethod.setType("x509");
                authMethod.setAuthLevel(authPolicyService.getAuthLevelByName(config.authLevel));
                authMethod.setExplicit(false);

                authMethod.setApacheFix(config.apacheFix).setCertHeaderName(config.certHeaderName)
                        .setSecurity(config.security).setClientCertTrust(config.clientCertTrust)
                        .setConditionExpression(config.conditionExpression).setProxyCertDn(config.proxyCertDn)
                        .setProxyCertTrust(config.proxyCertTrust).setSecurityHeaderName(config.securityHeaderName)
                        .setSharedSecret(config.sharedSecret).setUidExpression(config.uidExpression);

            } catch (UnknownAuthLevelException e) {
                LOG.error("Configuration error: Invalid authentication level in authentication method {}", config.name);
                System.exit(GlobalConstants.CONFIGURATION_ERROR);
            }

            authMethods.add(authMethod);
        }
    }

    private void verifyValues() {

        for (X509AuthMethod authMethod : authMethods) {

            if (authMethod.getName() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "X509 authentication configuration error: \"x509AuthMethods > name\" property must be set");

            if (authMethod.getUidExpression() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "X509 authentication configuration error: \"x509AuthMethods > uidExpression\" property must be set");

            if (authMethod.getConditionExpression() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "X509 authentication configuration error: \"x509AuthMethods > conditionExpression\" property must be set");

            if (authMethod.getClientCertTrust() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "X509 authentication configuration error: \"x509AuthMethods > clientCertTrust\" property must be set");

            if (!FileUtils.fileExists(authMethod.getClientCertTrust()))
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "X509 authentication configuration error: Client cert trust file " + authMethod.getClientCertTrust() + " doesn't exist");

            if (authMethod.getSecurity() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "X509 authentication configuration error: \"x509AuthMethods > security\" property must be set");

            if (!"native".equals(authMethod.getSecurity()) && !"ssl".equals(authMethod.getSecurity()) && !"shared-secret".equals(authMethod.getSecurity()))
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "X509 authentication configuration error: \"x509AuthMethods > security\" is invalid. Supported values: native, shared-secret, ssl");

            if ("shared-secret".equals(authMethod.getSecurity())) {
                if (authMethod.getCertHeaderName() == null)
                    IdentioServerApplication.quitOnConfigurationError(LOG,
                            "X509 authentication configuration error: \"x509AuthMethods > certHeaderName\" property must be set");

                if (authMethod.getSecurityHeaderName() == null)
                    IdentioServerApplication.quitOnConfigurationError(LOG,
                            "X509 authentication configuration error: \"x509AuthMethods > securityHeaderName\" property must be set");

                if (authMethod.getSharedSecret() == null)
                    IdentioServerApplication.quitOnConfigurationError(LOG,
                            "X509 authentication configuration error: \"x509AuthMethods > sharedSecret\" property must be set");
            }

            if ("ssl".equals(authMethod.getSecurity())) {
                if (authMethod.getProxyCertDn() == null)
                    IdentioServerApplication.quitOnConfigurationError(LOG,
                            "X509 authentication configuration error: \"x509AuthMethods > proxyCertDn\" property must be set");

                if (authMethod.getProxyCertTrust() == null)
                    IdentioServerApplication.quitOnConfigurationError(LOG,
                            "X509 authentication configuration error: \"x509AuthMethods > proxyCertTrust\" property must be set");

                if (!FileUtils.fileExists(authMethod.getProxyCertTrust()))
                    IdentioServerApplication.quitOnConfigurationError(LOG,
                            "X509 authentication configuration error: Proxy cert trust file " + authMethod.getProxyCertTrust() + " doesn't exist");
            }
        }
    }

    protected List<X509AuthMethod> getAuthMethods() {
        return authMethods;
    }
}
