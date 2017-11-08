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

package net.identio.server.service.oauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "oAuthServer")
public class OAuthConfiguration {

    // Configuration mapping handled by Spring Cloud config

    private String actorsFile;
    private String dataSource;
    private boolean jwtToken;

    public String getActorsFile() {
        return actorsFile;
    }

    public void setActorsFile(String actorsFile) {
        this.actorsFile = actorsFile;
    }

    public String getDataSource() {
        return dataSource;
    }

    public void setDataSource(String dataSource) {
        this.dataSource = dataSource;
    }

    public boolean isJwtToken() {
        return jwtToken;
    }

    public void setJwtToken(boolean jwtToken) {
        this.jwtToken = jwtToken;
    }

    // End: Configuration mapping handled by Spring Cloud config
}
