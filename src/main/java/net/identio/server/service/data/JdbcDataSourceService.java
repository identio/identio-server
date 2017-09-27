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

package net.identio.server.service.data;

import com.zaxxer.hikari.HikariDataSource;
import net.identio.server.model.DataSource;
import net.identio.server.service.configuration.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;

@Service
public class JdbcDataSourceService {

    private HashMap<String, HikariDataSource> dataSources = new HashMap<>();

    @Autowired
    public JdbcDataSourceService(ConfigurationService configurationService) {

        List<DataSource> dataSourceList =  configurationService.getConfiguration().getDataSourcesConfiguration().getDataSources();

        if (dataSourceList == null) return;

        for (DataSource dataSourceConfiguration : dataSourceList)
        {
            HikariDataSource ds = new HikariDataSource();

            ds.setMaximumPoolSize(10);
            ds.setDriverClassName(dataSourceConfiguration.getDriver());
            ds.setJdbcUrl(dataSourceConfiguration.getUrl());
            ds.setUsername(dataSourceConfiguration.getUsername());
            ds.setPassword(dataSourceConfiguration.getPassword());

            dataSources.put(dataSourceConfiguration.getName(), ds);
        }
    }

    public HikariDataSource getDataSource(String name) {
        return dataSources.get(name);
    }
}
