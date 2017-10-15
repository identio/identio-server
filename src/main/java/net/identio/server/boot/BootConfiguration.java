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

    private static final String fileConfigOptionName = "identio.config";
    private static final String gitUriConfigOptionName = "identio.config.git.uri";
    private static final String configServerConfigOptionName = "identio.config.server.uri";
    private static final String usernameConfigOptionName = "identio.config.username";
    private static final String passwordConfigOptionName = "identio.config.password";

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

        if (configOptions.containsKey(fileConfigOptionName))
            setupFileConfiguration(configOptions.get(fileConfigOptionName), application);

        if (configOptions.containsKey(gitUriConfigOptionName))
            setupGitConfiguration(configOptions.get(gitUriConfigOptionName),
                    configOptions.get(usernameConfigOptionName),
                    configOptions.get(passwordConfigOptionName));

        if (configOptions.containsKey(configServerConfigOptionName))
            setupConfigServerConfiguration(configOptions.get(configServerConfigOptionName),
                    configOptions.get(usernameConfigOptionName),
                    configOptions.get(passwordConfigOptionName));


    }

    private static void addConfigOptionsFromSysEnv(HashMap<String, String> configOptions) {

        if (System.getenv(fileConfigOptionName) != null)
            configOptions.put(fileConfigOptionName, System.getenv(fileConfigOptionName));
        if (System.getenv(gitUriConfigOptionName) != null)
            configOptions.put(gitUriConfigOptionName, System.getenv(gitUriConfigOptionName));
        if (System.getenv(usernameConfigOptionName) != null)
            configOptions.put(usernameConfigOptionName, System.getenv(usernameConfigOptionName));
        if (System.getenv(passwordConfigOptionName) != null)
            configOptions.put(passwordConfigOptionName, System.getenv(passwordConfigOptionName));
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
        System.setProperty("spring.cloud.config.name",
                configPath.getFileName().toString().replaceAll(".yml", ""));
        System.setProperty("spring.cloud.config.server.native.searchLocations", "file:" +
                configPath.getParent().toString());
    }

    private static void setupGitConfiguration(String uri, String username, String password) {

        System.setProperty("spring.cloud.config.server.bootstrap", "true");
        System.setProperty("spring.cloud.config.server.git.uri", uri);
        System.setProperty("spring.cloud.config.name", "identio-config.yml");

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
