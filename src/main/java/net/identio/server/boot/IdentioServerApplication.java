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

import org.slf4j.Logger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableAutoConfiguration(exclude = MongoAutoConfiguration.class)
@ComponentScan(basePackages = {"net.identio.server"})
@EnableScheduling
@EnableConfigurationProperties
public class IdentioServerApplication {

    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(IdentioServerApplication.class);

        BootConfiguration.setupConfiguration(args, application);
        BootConfiguration.setupDefaultConfigurationValue();

        application.run(args);
    }

    public static void quitOnConfigurationError(Logger log, String message) {

        log.error(message);
        System.exit(GlobalConstants.CONFIGURATION_ERROR);
    }

    public static void quitOnStartupError(Logger log, String message) {

        log.error(message);
        System.exit(GlobalConstants.CONFIGURATION_ERROR);
    }
}
