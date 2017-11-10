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

import org.springframework.boot.SpringApplication;

import java.net.URI;
import java.util.HashMap;

public class BootConfiguration {

    private static final String FILE_CONFIG_OPTION = "identio.config";

    private static final String GIT_CONFIG_OPTION = "identio.config.git.uri";
    private static final String GIT_CONFIG_USERNAME_OPTION = "identio.config.git.username";
    private static final String GIT_CONFIG_PASSWORD_OPTION = "identio.config.git.password";

    private static final String CONFIG_SERVER_OPTION = "identio.config.server.uri";
    private static final String CONFIG_SERVER_USERNAME_OPTION = "identio.config.server.username";
    private static final String CONFIG_SERVER_PASSWORD_OPTION = "identio.config.server.password";

    private static final String VAULT_CONFIG_OPTION = "identio.config.vault.uri";
    private static final String VAULT_CONFIG_ROLE_ID_OPTION = "identio.config.vault.role-id";
    private static final String VAULT_CONFIG_SECRET_ID_OPTION = "identio.config.vault.secret-id";
    private static final String VAULT_CONFIG_TRUST_PATH = "identio.config.vault.trust-store.path";
    private static final String VAULT_CONFIG_TRUST_PASSWORD = "identio.config.vault.trust-store.password";

    private static final String WORK_DIRECTORY_OPTION = "identio.work.directory";

    // Default values
    private static final String DEFAULT_WORK_DIRECTORY = "config/work";
    private static final String DEFAULT_STATIC_RESOURCES_CACHE_PERIOD = "500000";

    public static void setupDefaultConfigurationValue() {

        // Add a default cache period for static resources
        System.setProperty("spring.resources.cache-period", DEFAULT_STATIC_RESOURCES_CACHE_PERIOD);

        // By default, disable Vault integration as it will try to autoconnect to a potentially non-existent
        // Vault server
        System.setProperty("spring.cloud.vault.enabled", "false");

        // Set application name
        System.setProperty("spring.application.name", "identio");
    }

    public static void setupConfiguration(String[] args, SpringApplication application) {

        HashMap<String, String> configOptions = new HashMap<>();

        // First we read the config options from the system env
        addConfigOptionsFromSysEnv(configOptions);

        setupWorkDirectory(configOptions);

        if (args != null && args.length != 0)
            addConfigOptionsFromCmdLine(configOptions, args);

        if (configOptions.containsKey(FILE_CONFIG_OPTION))
            setupFileConfiguration(configOptions, application);

        if (configOptions.containsKey(GIT_CONFIG_OPTION))
            setupGitConfiguration(configOptions);

        if (configOptions.containsKey(CONFIG_SERVER_OPTION))
            setupConfigServerConfiguration(configOptions);

        if (configOptions.containsKey(VAULT_CONFIG_OPTION))
            setupVaultConfiguration(configOptions);

    }

    private static void setupWorkDirectory(HashMap<String, String> configOptions) {

        if (!configOptions.containsKey(WORK_DIRECTORY_OPTION)) {
            configOptions.put(WORK_DIRECTORY_OPTION, DEFAULT_WORK_DIRECTORY);
            System.setProperty(WORK_DIRECTORY_OPTION, DEFAULT_WORK_DIRECTORY);
        }
    }

    private static void addConfigOptionsFromSysEnv(HashMap<String, String> configOptions) {

        addOptionFromSysEnv(FILE_CONFIG_OPTION, configOptions);

        addOptionFromSysEnv(GIT_CONFIG_OPTION, configOptions);
        addOptionFromSysEnv(GIT_CONFIG_USERNAME_OPTION, configOptions);
        addOptionFromSysEnv(GIT_CONFIG_PASSWORD_OPTION, configOptions);

        addOptionFromSysEnv(CONFIG_SERVER_OPTION, configOptions);
        addOptionFromSysEnv(CONFIG_SERVER_USERNAME_OPTION, configOptions);
        addOptionFromSysEnv(CONFIG_SERVER_PASSWORD_OPTION, configOptions);

        addOptionFromSysEnv(VAULT_CONFIG_OPTION, configOptions);
        addOptionFromSysEnv(VAULT_CONFIG_ROLE_ID_OPTION, configOptions);
        addOptionFromSysEnv(VAULT_CONFIG_SECRET_ID_OPTION, configOptions);
        addOptionFromSysEnv(VAULT_CONFIG_TRUST_PATH, configOptions);
        addOptionFromSysEnv(VAULT_CONFIG_TRUST_PASSWORD, configOptions);

        addOptionFromSysEnv(WORK_DIRECTORY_OPTION, configOptions);
    }

    private static void addOptionFromSysEnv(String optionName, HashMap<String, String> configOptions) {

        if (System.getenv(optionName) != null)
            configOptions.put(optionName, System.getenv(optionName));
    }

    private static void addConfigOptionsFromCmdLine(HashMap<String, String> configOptions, String[] args) {

        for (String arg : args) {

            String[] optionElements = arg.split("=");

            configOptions.put(optionElements[0].replaceAll("--", ""), optionElements[1]);
        }
    }

    private static void setupFileConfiguration(HashMap<String, String> configOptions,
                                               SpringApplication application) {

        application.setAdditionalProfiles("native");

        System.setProperty("spring.cloud.config.server.bootstrap", "true");

        System.setProperty("spring.cloud.config.server.native.searchLocations", "file:" +
                configOptions.get(FILE_CONFIG_OPTION));

    }

    private static void setupGitConfiguration(HashMap<String, String> configOptions) {

        System.setProperty("spring.cloud.config.server.bootstrap", "true");
        System.setProperty("spring.cloud.config.server.git.uri", configOptions.get(GIT_CONFIG_OPTION));

        if (configOptions.get(GIT_CONFIG_USERNAME_OPTION) != null && configOptions.get(GIT_CONFIG_PASSWORD_OPTION) != null) {
            System.setProperty("spring.cloud.config.server.git.username", configOptions.get(GIT_CONFIG_USERNAME_OPTION));
            System.setProperty("spring.cloud.config.server.git.password", configOptions.get(GIT_CONFIG_PASSWORD_OPTION));
        }

        // Setup local path where the repository is cloned
        System.setProperty("spring.cloud.config.server.git.basedir", configOptions.get(WORK_DIRECTORY_OPTION));
    }

    private static void setupConfigServerConfiguration(HashMap<String, String> configOptions) {

        System.setProperty("spring.cloud.config.uri", configOptions.get(CONFIG_SERVER_OPTION));

        if (configOptions.get(CONFIG_SERVER_USERNAME_OPTION) != null && configOptions.get(CONFIG_SERVER_PASSWORD_OPTION) != null) {
            System.setProperty("spring.cloud.config.username", configOptions.get(CONFIG_SERVER_USERNAME_OPTION));
            System.setProperty("spring.cloud.config.password", configOptions.get(CONFIG_SERVER_PASSWORD_OPTION));
        }
    }

    private static void setupVaultConfiguration(HashMap<String, String> configOptions) {

        // Parse uri
        URI vaultUri = URI.create(configOptions.get(VAULT_CONFIG_OPTION));

        System.setProperty("spring.cloud.vault.enabled", "true");
        System.setProperty("spring.cloud.vault.host", vaultUri.getHost());
        System.setProperty("spring.cloud.vault.port", String.valueOf(vaultUri.getPort()));
        System.setProperty("spring.cloud.vault.scheme", vaultUri.getScheme());
        System.setProperty("spring.cloud.vault.connection-timeout", String.valueOf(5000));
        System.setProperty("spring.cloud.vault.read-timeout", String.valueOf(15000));

        // Authentication
        System.setProperty("spring.cloud.vault.authentication", "APPROLE");
        System.setProperty("spring.cloud.vault.app-role.role-id", configOptions.get(VAULT_CONFIG_ROLE_ID_OPTION));
        System.setProperty("spring.cloud.vault.app-role.secret-id", configOptions.get(VAULT_CONFIG_SECRET_ID_OPTION));

        if ("https".equals(vaultUri.getScheme())) {
            System.setProperty("spring.cloud.vault.ssl.trust-store", configOptions.get(VAULT_CONFIG_TRUST_PATH));
            System.setProperty("spring.cloud.vault.ssl.trust-store-password", configOptions.get(VAULT_CONFIG_TRUST_PASSWORD));
        }
    }
}
