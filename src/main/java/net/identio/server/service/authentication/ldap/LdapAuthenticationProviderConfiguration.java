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

package net.identio.server.service.authentication.ldap;

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
@ConfigurationProperties(prefix = "authMethodConfiguration")
public class LdapAuthenticationProviderConfiguration implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(LdapAuthenticationProviderConfiguration.class);

    private List<LdapAuthMethod> authMethods = new ArrayList<>();

    @Autowired
    private AuthPolicyService authPolicyService;

    /// Configuration mapping handled by Spring Cloud config

    private List<LdapAuthenticationProviderConfiguration.LdapAuthMethodConfiguration> ldapAuthMethods = new ArrayList<>();

    public List<LdapAuthMethodConfiguration> getLdapAuthMethods() {
        return ldapAuthMethods;
    }

    public void setLdapAuthMethods(List<LdapAuthMethodConfiguration> ldapAuthMethods) {
        this.ldapAuthMethods = ldapAuthMethods;
    }

    public static class LdapAuthMethodConfiguration {

        private String name;
        private String logoFileName;
        private String authLevel;
        private String baseDn;
        private List<String> ldapUrl = new ArrayList<>();
        private String proxyUser;
        private String proxyPassword;
        private String trustCert;
        private String userSearchFilter;
        private LdapPoolConfig poolConfig = new LdapPoolConfig();

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

        public String getBaseDn() {
            return baseDn;
        }

        public void setBaseDn(String baseDn) {
            this.baseDn = nullIfEmpty(baseDn);
        }

        public List<String> getLdapUrl() {
            return ldapUrl;
        }

        public void setLdapUrl(List<String> ldapUrl) {
            this.ldapUrl = ldapUrl;
        }

        public String getProxyUser() {
            return proxyUser;
        }

        public void setProxyUser(String proxyUser) {
            this.proxyUser = nullIfEmpty(proxyUser);
        }

        public String getProxyPassword() {
            return proxyPassword;
        }

        public void setProxyPassword(String proxyPassword) {
            this.proxyPassword = nullIfEmpty(proxyPassword);
        }

        public String getTrustCert() {
            return trustCert;
        }

        public void setTrustCert(String trustCert) {
            this.trustCert = nullIfEmpty(trustCert);
        }

        public String getUserSearchFilter() {
            return userSearchFilter;
        }

        public void setUserSearchFilter(String userSearchFilter) {
            this.userSearchFilter = nullIfEmpty(userSearchFilter);
        }

        public LdapPoolConfig getPoolConfig() {
            return poolConfig;
        }

        public void setPoolConfig(LdapPoolConfig poolConfig) {
            this.poolConfig = poolConfig;
        }
    }

    public static class LdapPoolConfig {

        private int minIdleConnections = 4;
        private int maxIdleConnections = 8;
        private boolean testWhileIdle;
        private boolean testOnBorrow;
        private String testRequestFilter = "(objectclass=*)";
        private int timeBetweenEvictionRuns = 30;
        private int numTestsPerEvictionRun = 4;
        private int minEvictableIdleTime = -1;

        public int getMinIdleConnections() {
            return minIdleConnections;
        }

        public void setMinIdleConnections(int minIdleConnections) {
            this.minIdleConnections = minIdleConnections;
        }

        public int getMaxIdleConnections() {
            return maxIdleConnections;
        }

        public void setMaxIdleConnections(int maxIdleConnections) {
            this.maxIdleConnections = maxIdleConnections;
        }

        public boolean isTestWhileIdle() {
            return testWhileIdle;
        }

        public void setTestWhileIdle(boolean testWhileIdle) {
            this.testWhileIdle = testWhileIdle;
        }

        public boolean isTestOnBorrow() {
            return testOnBorrow;
        }

        public void setTestOnBorrow(boolean testOnBorrow) {
            this.testOnBorrow = testOnBorrow;
        }

        public String getTestRequestFilter() {
            return testRequestFilter;
        }

        public void setTestRequestFilter(String testRequestFilter) {
            this.testRequestFilter = nullIfEmpty(testRequestFilter);
        }

        public int getTimeBetweenEvictionRuns() {
            return timeBetweenEvictionRuns;
        }

        public void setTimeBetweenEvictionRuns(int timeBetweenEvictionRuns) {
            this.timeBetweenEvictionRuns = timeBetweenEvictionRuns;
        }

        public int getNumTestsPerEvictionRun() {
            return numTestsPerEvictionRun;
        }

        public void setNumTestsPerEvictionRun(int numTestsPerEvictionRun) {
            this.numTestsPerEvictionRun = numTestsPerEvictionRun;
        }

        public int getMinEvictableIdleTime() {
            return minEvictableIdleTime;
        }

        public void setMinEvictableIdleTime(int minEvictableIdleTime) {
            this.minEvictableIdleTime = minEvictableIdleTime;
        }
    }

    /// End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() {

        indexAuthMethods();
        verifyValues();

    }

    private void indexAuthMethods(){

        for (LdapAuthMethodConfiguration config : ldapAuthMethods) {

            LdapAuthMethod authMethod = new LdapAuthMethod();

            try {

                authMethod.setName(config.name);
                authMethod.setType("ldap");
                authMethod.setAuthLevel(authPolicyService.getAuthLevelByName(config.authLevel));
                authMethod.setExplicit(true);

                authMethod.setBaseDn(config.baseDn).setLdapUrl(config.ldapUrl).setPoolConfig(config.poolConfig)
                        .setProxyPassword(config.proxyPassword).setProxyUser(config.proxyUser)
                        .setTrustCert(config.trustCert).setUserSearchFilter(config.userSearchFilter);

            } catch (UnknownAuthLevelException e) {
                LOG.error("Configuration error: Invalid authentication level in authentication method {}", config.name);
                System.exit(GlobalConstants.CONFIGURATION_ERROR);
            }

            authMethods.add(authMethod);
        }
    }

    private void verifyValues() {

        for (LdapAuthMethod authMethod : authMethods) {

            if (authMethod.getName() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "LDAP configuration error: \"ldapAuthMethods > name\" property must be set");

            if (authMethod.getBaseDn() == null)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "LDAP configuration error: \"ldapAuthMethods > baseDn\" property must be set");

            if (authMethod.getLdapUrl() == null || authMethod.getLdapUrl().size() == 0)
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "LDAP configuration error: \"ldapAuthMethods > ldapUrl\" property must be set");

            if (authMethod.getTrustCert() != null && !FileUtils.fileExists(authMethod.getTrustCert()))
                IdentioServerApplication.quitOnConfigurationError(LOG,
                        "LDAP configuration error: Trust cert " + authMethod.getTrustCert() + " doesn't exist");
        }
    }

    protected List<LdapAuthMethod> getAuthMethods() {
        return authMethods;
    }
}