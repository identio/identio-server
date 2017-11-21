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

package net.identio.server.service.authpolicy;

import net.identio.server.model.AppAuthLevel;
import net.identio.server.model.AuthLevel;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import static net.identio.server.utils.MiscUtils.nullIfEmpty;

@Configuration
@ConfigurationProperties(prefix = "authPolicy")
public class AuthPolicyConfiguration implements InitializingBean {

    private HashMap<String, AuthLevel> authLevelByName = new HashMap<>();
    private HashMap<String, AuthLevel> authLevelByUrn = new HashMap<>();
    private HashMap<String, AppAuthLevel> authLevelByApp = new HashMap<>();

    private AppAuthLevel enrichedDefaultAppLevel;

    /// Configuration mapping handled by Spring Cloud config

    private List<AuthLevelConfiguration> authLevels = new ArrayList<>();
    private AppAuthLevelConfiguration defaultAuthLevel;
    private List<AppAuthLevelConfiguration> applicationSpecificAuthLevel = new ArrayList<>();

    public List<AuthLevelConfiguration> getAuthLevels() {
        return authLevels;
    }

    public AppAuthLevelConfiguration getDefaultAuthLevel() {
        return defaultAuthLevel;
    }

    public List<AppAuthLevelConfiguration> getApplicationSpecificAuthLevel() {
        return applicationSpecificAuthLevel;
    }

    public void setAuthLevels(List<AuthLevelConfiguration> authLevels) {
        this.authLevels = authLevels;
    }

    public void setDefaultAuthLevel(AppAuthLevelConfiguration defaultAuthLevel) {
        this.defaultAuthLevel = defaultAuthLevel;
    }

    public void setApplicationSpecificAuthLevel(List<AppAuthLevelConfiguration> applicationSpecificAuthLevel) {
        this.applicationSpecificAuthLevel = applicationSpecificAuthLevel;
    }

    public static class AuthLevelConfiguration {

        private String name;
        private String urn;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = nullIfEmpty(name);
        }

        public String getUrn() {
            return urn;
        }

        public void setUrn(String urn) {
            this.urn = nullIfEmpty(urn);
        }

    }

    public static class AppAuthLevelConfiguration {

        private String appName;
        private String authLevel;
        private String comparison;

        public String getAppName() {
            return appName;
        }

        public void setAppName(String appName) {
            this.appName = nullIfEmpty(appName);
        }

        public String getAuthLevel() {
            return authLevel;
        }

        public void setAuthLevel(String authLevel) {
            this.authLevel = nullIfEmpty(authLevel);
        }

        public String getComparison() {
            return comparison;
        }

        public void setComparison(String comparison) {
            this.comparison = nullIfEmpty(comparison);
        }
    }

    /// End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() {

        // Index auth levels
        indexAuthLevels();

        // Index app-specific auth levels
        indexAppSpecificAuthLevels();

        parseDefaultAuthLevel();
    }

    private void indexAuthLevels() {

        int strength = 0;

        for (AuthLevelConfiguration authLevelConfig : authLevels) {

            AuthLevel authLevel = new AuthLevel();
            authLevel.setName(authLevelConfig.name);
            authLevel.setUrn(authLevelConfig.urn);
            authLevel.setStrength(strength);

            authLevelByName.put(authLevel.getName(), authLevel);
            authLevelByUrn.put(authLevel.getUrn(), authLevel);

            strength++;
        }
    }

    private void indexAppSpecificAuthLevels() {

        for (AppAuthLevelConfiguration authLevelConfig : applicationSpecificAuthLevel) {

            AppAuthLevel authLevel = new AppAuthLevel();
            authLevel.setAppName(authLevelConfig.appName);
            authLevel.setComparison(authLevelConfig.comparison);
            authLevel.setAuthLevel(authLevelByName.get(authLevelConfig.authLevel));

            authLevelByApp.put(authLevelConfig.appName, authLevel);
        }
    }

    private void parseDefaultAuthLevel() {

        if (defaultAuthLevel == null) return;

        enrichedDefaultAppLevel = new AppAuthLevel();
        enrichedDefaultAppLevel.setAppName(defaultAuthLevel.appName);
        enrichedDefaultAppLevel.setAuthLevel(authLevelByName.get(defaultAuthLevel.authLevel));
        enrichedDefaultAppLevel.setComparison(defaultAuthLevel.comparison);
    }

    protected AuthLevel getAuthLevelByName(String name) {
        return authLevelByName.get(name);
    }

    protected AuthLevel getAuthLevelByUrn(String urn) {
        return authLevelByUrn.get(urn);
    }

    protected AppAuthLevel getAuthLevelByApp(String appName) {
        return authLevelByApp.get(appName);
    }

    protected AppAuthLevel getEnrichedDefaultAppLevel() {
        return enrichedDefaultAppLevel;
    }

    protected Collection<AuthLevel> getAllAuthLevels() {
        return authLevelByName.values();
    }
}
