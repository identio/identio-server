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

package net.identio.server.service.authentication.local;

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
@ConfigurationProperties(prefix = "authMethodConfiguration")
public class LocalAuthenticationProviderConfiguration implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(LocalAuthenticationProviderConfiguration.class);

    private static final String DEFAULT_USER_FILE_PATH = "config/users.yml";

    private List<LocalAuthMethod> authMethods = new ArrayList<>();

    @Autowired
    private AuthPolicyService authPolicyService;

    /// Configuration mapping handled by Spring Cloud config

    private List<LocalAuthenticationProviderConfiguration.LocalAuthMethodConfiguration> localAuthMethods = new ArrayList<>();

    public List<LocalAuthMethodConfiguration> getLocalAuthMethods() {
        return localAuthMethods;
    }

    public void setLocalAuthMethods(List<LocalAuthMethodConfiguration> localAuthMethods) {
        this.localAuthMethods = localAuthMethods;
    }

    public static class LocalAuthMethodConfiguration {

        private String name;
        private String logoFileName;
        private String authLevel;
        private String userFilePath;

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

        public String getUserFilePath() {
            return userFilePath;
        }

        public void setUserFilePath(String userFilePath) {
            this.userFilePath = nullIfEmpty(userFilePath);
        }
    }

    /// End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() {

        indexAuthMethods();
        verifyValues();
    }

    private void indexAuthMethods() {


        for (LocalAuthMethodConfiguration config : localAuthMethods) {

            LocalAuthMethod authMethod = new LocalAuthMethod();

            try {

                authMethod.setName(config.name);
                authMethod.setType("local");
                authMethod.setAuthLevel(authPolicyService.getAuthLevelByName(config.authLevel));
                authMethod.setExplicit(true);
                authMethod.setUserFilePath(config.userFilePath != null ? config.userFilePath : DEFAULT_USER_FILE_PATH);

            } catch (UnknownAuthLevelException e) {
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "Configuration error: Invalid authentication level in authentication method " + config.name);
            }

            authMethods.add(authMethod);
        }

    }

    private void verifyValues() {

        for (LocalAuthMethod authMethod : authMethods) {

            if (authMethod.getName() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "Local authentication configuration error: \"localAuthMethods > name\" property must be set");

            if (!FileUtils.fileExists(authMethod.getUserFilePath()))
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "Local authentication configuration error: User file " + authMethod.getUserFilePath() + " doesn't exist");
        }
    }

    protected List<LocalAuthMethod> getAuthMethods() {
        return authMethods;
    }
}
