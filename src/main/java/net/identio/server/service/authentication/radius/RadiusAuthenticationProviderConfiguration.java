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

import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.service.authpolicy.AuthPolicyService;
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
public class RadiusAuthenticationProviderConfiguration implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(RadiusAuthenticationProviderConfiguration.class);

    private static final int DEFAULT_ACCOUNT_PORT = 1813;
    private static final int DEFAULT_AUTH_PORT = 1812;
    private static final int DEFAULT_TIMEOUT = 5000;

    private List<RadiusAuthMethod> authMethods = new ArrayList<>();

    @Autowired
    private AuthPolicyService authPolicyService;

    /// Configuration mapping handled by Spring Cloud config

    private List<RadiusAuthenticationProviderConfiguration.RadiusAuthMethodConfiguration> radius = new ArrayList<>();

    public List<RadiusAuthMethodConfiguration> getRadius() {
        return radius;
    }

    public void setRadius(List<RadiusAuthMethodConfiguration> radius) {
        this.radius = radius;
    }

    public static class RadiusAuthMethodConfiguration {

        private String name;
        private String logoFileName;
        private String authLevel;
        private List<String> radiusHost = new ArrayList<>();
        private int accountPort;
        private int authPort;
        private String sharedSecret;
        private int timeout;

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

        public List<String> getRadiusHost() {
            return radiusHost;
        }

        public void setRadiusHost(List<String> radiusHost) {
            this.radiusHost = radiusHost;
        }

        public int getAccountPort() {
            return accountPort;
        }

        public void setAccountPort(int accountPort) {
            this.accountPort = accountPort;
        }

        public int getAuthPort() {
            return authPort;
        }

        public void setAuthPort(int authPort) {
            this.authPort = authPort;
        }

        public String getSharedSecret() {
            return sharedSecret;
        }

        public void setSharedSecret(String sharedSecret) {
            this.sharedSecret = nullIfEmpty(sharedSecret);
        }

        public int getTimeout() {
            return timeout;
        }

        public void setTimeout(int timeout) {
            this.timeout = timeout;
        }
    }

    /// End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() {

        indexAuthMethods();
        verifyValues();
    }

    private void indexAuthMethods() {

        for (RadiusAuthMethodConfiguration config : radius) {

            RadiusAuthMethod authMethod = new RadiusAuthMethod();

            try {

                authMethod.setName(config.name);
                authMethod.setType("radius");
                authMethod.setAuthLevel(authPolicyService.getAuthLevelByName(config.authLevel));
                authMethod.setExplicit(true);

                authMethod.setAccountPort(config.accountPort = config.accountPort != 0 ? config.accountPort : DEFAULT_ACCOUNT_PORT )
                        .setAuthPort(config.authPort = config.authPort != 0 ? config.authPort : DEFAULT_AUTH_PORT )
                        .setSharedSecret(config.sharedSecret)
                        .setTimeout(config.timeout = config.timeout != 0 ? config.timeout : DEFAULT_TIMEOUT)
                        .setRadiusHost(config.radiusHost);

            } catch (UnknownAuthLevelException e) {
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "Configuration error: Invalid authentication level in authentication method " + config.name);
            }

            authMethods.add(authMethod);
        }
    }

    private void verifyValues() {

        for (RadiusAuthMethod authMethod : authMethods) {

            if (authMethod.getName() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "Radius authentication configuration error: \"radiusAuthMethods > name\" property must be set");

            if (authMethod.getRadiusHost() == null || authMethod.getRadiusHost().size() == 0)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "Radius configuration error: \"radiusAuthMethods > radiusHost\" property must be set");

            if (authMethod.getSharedSecret() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "Radius configuration error: \"radiusAuthMethods > sharedSecret\" property must be set");
        }
    }

    protected List<RadiusAuthMethod> getAuthMethods() {
        return authMethods;
    }

}
