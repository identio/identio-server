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

package net.identio.server.service.authentication.saml;

import net.identio.server.boot.GlobalConstants;
import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.model.AuthLevel;
import net.identio.server.service.authpolicy.AuthPolicyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import static net.identio.server.utils.MiscUtils.nullIfEmpty;

@Configuration
@ConfigurationProperties(prefix = "authMethodConfiguration")
public class SamlAuthenticationProviderConfiguration implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(SamlAuthenticationProviderConfiguration.class);

    private List<SamlAuthMethod> authMethods = new ArrayList<>();

    @Autowired
    private AuthPolicyService authPolicyService;

    /// Configuration mapping handled by Spring Cloud config

    private List<SamlAuthMethodConfiguration> samlAuthMethods = new ArrayList<>();

    public List<SamlAuthMethodConfiguration> getSamlAuthMethods() {
        return samlAuthMethods;
    }

    public void setSamlAuthMethods(List<SamlAuthMethodConfiguration> samlAuthMethods) {
        this.samlAuthMethods = samlAuthMethods;
    }

    public static class SamlAuthMethodConfiguration {

        private String name;
        private boolean certificateCheckEnabled;
        private String logoFileName;
        private String metadata;
        private SamlAuthMapConfiguration samlAuthMap;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = nullIfEmpty(name);
        }

        public boolean isCertificateCheckEnabled() {
            return certificateCheckEnabled;
        }

        public void setCertificateCheckEnabled(boolean certificateCheckEnabled) {
            this.certificateCheckEnabled = certificateCheckEnabled;
        }

        public String getLogoFileName() {
            return logoFileName;
        }

        public void setLogoFileName(String logoFileName) {
            this.logoFileName = nullIfEmpty(logoFileName);
        }

        public String getMetadata() {
            return metadata;
        }

        public void setMetadata(String metadata) {
            this.metadata = nullIfEmpty(metadata);
        }

        public SamlAuthMapConfiguration getSamlAuthMap() {
            return samlAuthMap;
        }

        public void setSamlAuthMap(SamlAuthMapConfiguration samlAuthMap) {
            this.samlAuthMap = samlAuthMap;
        }
    }

    public static class SamlAuthMapConfiguration {

        private HashMap<String, String> in = new HashMap<>();
        private HashMap<String, String> out = new HashMap<>();

        public HashMap<String, String> getIn() {
            return in;
        }

        public void setIn(HashMap<String, String> in) {
            this.in = in;
        }

        public HashMap<String, String> getOut() {
            return out;
        }

        public void setOut(HashMap<String, String> out) {
            this.out = out;
        }
    }

    /// End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() {

        indexAuthMethods();
        verifyValues();
    }

    private void indexAuthMethods() {

        for (SamlAuthMethodConfiguration config : samlAuthMethods) {

            SamlAuthMethod authMethod = new SamlAuthMethod();

            authMethod.setName(config.name);
            authMethod.setType("saml");
            authMethod.setExplicit(true);
            authMethod.setLogoFileName(config.logoFileName);

            authMethod.setCertificateCheckEnabled(config.certificateCheckEnabled).setMetadata(config.metadata);

            // Parse Saml Authentication mapping
            SamlAuthMap map = new SamlAuthMap();
            authMethod.setSamlAuthMap(map);

            HashMap<String, AuthLevel> in = new HashMap<>();
            HashMap<AuthLevel, String> out = new HashMap<>();

            map.setIn(in);
            map.setOut(out);

            config.samlAuthMap.in.forEach((k, v) -> {
                try {
                    in.put(k, authPolicyService.getAuthLevelByName(v));
                } catch (UnknownAuthLevelException e) {
                    LOG.error("Configuration error: Invalid authentication level in authentication method {}", config.name);
                    System.exit(GlobalConstants.CONFIGURATION_ERROR);
                }
            });

            config.samlAuthMap.out.forEach((k, v) -> {
                try {
                    out.put(authPolicyService.getAuthLevelByName(k), v);
                } catch (UnknownAuthLevelException e) {
                    LOG.error("Configuration error: Invalid authentication level in authentication method {}", config.name);
                    System.exit(GlobalConstants.CONFIGURATION_ERROR);
                }
            });

            authMethods.add(authMethod);
        }
    }

    private void verifyValues() {

        for (SamlAuthMethod authMethod : authMethods) {

            if (authMethod.getName() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "SAML proxy authentication configuration error: \"samlAuthMethods > name\" property must be set");

            if (authMethod.getMetadata() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "SAML proxy authentication configuration error: \"samlAuthMethods > metadata\" property must be set");
        }
    }

    protected List<SamlAuthMethod> getAuthMethods() {
        return authMethods;
    }
}
