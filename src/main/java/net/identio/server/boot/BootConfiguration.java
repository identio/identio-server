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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

public class BootConfiguration {

    private static final String FILE_CONFIG_OPTION = "identio.config";

    private static final String GIT_CONFIG_OPTION = "identio.config.git.uri";
    private static final String GIT_CONFIG_USERNAME_OPTION = "identio.config.git.username";
    private static final String GIT_CONFIG_PASSWORD_OPTION = "identio.config.git.password";

    private static final String CONFIG_SERVER_OPTION = "identio.config.server.uri";
    private static final String CONFIG_SERVER_USERNAME_OPTION = "identio.config.server.username";
    private static final String CONFIG_SERVER_PASSWORD_OPTION = "identio.config.server.password";

    public static void setupDefaultConfigurationValue() {

        // Add a default cache period for static resources
        System.setProperty("spring.resources.cache-period", "500000");
    }

    public static void setupConfiguration(String[] args, SpringApplication application) {

        HashMap<String, String> configOptions = new HashMap<>();

        // First we read the config options from the system env
        addConfigOptionsFromSysEnv(configOptions);

        if (args != null && args.length != 0)
            addConfigOptionsFromCmdLine(configOptions, args);

        if (configOptions.containsKey(FILE_CONFIG_OPTION))
            setupFileConfiguration(configOptions.get(FILE_CONFIG_OPTION), application);

        if (configOptions.containsKey(GIT_CONFIG_OPTION))
            setupGitConfiguration(configOptions.get(GIT_CONFIG_OPTION),
                    configOptions.get(GIT_CONFIG_USERNAME_OPTION),
                    configOptions.get(GIT_CONFIG_PASSWORD_OPTION));

        if (configOptions.containsKey(CONFIG_SERVER_OPTION))
            setupConfigServerConfiguration(configOptions.get(CONFIG_SERVER_OPTION),
                    configOptions.get(CONFIG_SERVER_USERNAME_OPTION),
                    configOptions.get(CONFIG_SERVER_PASSWORD_OPTION));
    }

    private static void addConfigOptionsFromSysEnv(HashMap<String, String> configOptions) {

        if (System.getenv(FILE_CONFIG_OPTION) != null)
            configOptions.put(FILE_CONFIG_OPTION, System.getenv(FILE_CONFIG_OPTION));

        if (System.getenv(GIT_CONFIG_OPTION) != null)
            configOptions.put(GIT_CONFIG_OPTION, System.getenv(GIT_CONFIG_OPTION));
        if (System.getenv(GIT_CONFIG_USERNAME_OPTION) != null)
            configOptions.put(GIT_CONFIG_USERNAME_OPTION, System.getenv(GIT_CONFIG_USERNAME_OPTION));
        if (System.getenv(GIT_CONFIG_PASSWORD_OPTION) != null)
            configOptions.put(GIT_CONFIG_PASSWORD_OPTION, System.getenv(GIT_CONFIG_PASSWORD_OPTION));

        if (System.getenv(CONFIG_SERVER_OPTION) != null)
            configOptions.put(CONFIG_SERVER_OPTION, System.getenv(CONFIG_SERVER_OPTION));
        if (System.getenv(CONFIG_SERVER_USERNAME_OPTION) != null)
            configOptions.put(CONFIG_SERVER_USERNAME_OPTION, System.getenv(CONFIG_SERVER_USERNAME_OPTION));
        if (System.getenv(CONFIG_SERVER_PASSWORD_OPTION) != null)
            configOptions.put(CONFIG_SERVER_PASSWORD_OPTION, System.getenv(CONFIG_SERVER_PASSWORD_OPTION));
    }

    private static void addConfigOptionsFromCmdLine(HashMap<String, String> configOptions, String[] args) {

        for (String arg : args) {

            String[] optionElements = arg.split("=");

            configOptions.put(optionElements[0].replaceAll("--", ""), optionElements[1]);
        }
    }

    private static void setupFileConfiguration(String file, SpringApplication application) {

        application.setAdditionalProfiles("native");

        Path configPath = Paths.get(file);

        System.setProperty("spring.cloud.config.server.bootstrap", "true");
        System.setProperty("spring.config.name",
                configPath.getFileName().toString().replaceAll(".yml", ""));
        System.setProperty("spring.cloud.config.server.native.searchLocations", "file:" +
                configPath.getParent().toString());
    }

    private static void setupGitConfiguration(String uri, String username, String password) {

        System.setProperty("spring.cloud.config.server.bootstrap", "true");
        System.setProperty("spring.cloud.config.server.git.uri", uri);
        System.setProperty("spring.config.name", "identio-config");

        if (username != null) {
            System.setProperty("spring.cloud.config.server.git.username", username);
            System.setProperty("spring.cloud.config.server.git.password", password);
        }
    }

    private static void setupConfigServerConfiguration(String uri, String username, String password) {

        System.setProperty("spring.cloud.config.uri", uri);

        if (username != null) {
            System.setProperty("spring.cloud.config.username", username);
            System.setProperty("spring.cloud.config.password", password);
        }
    }
}
