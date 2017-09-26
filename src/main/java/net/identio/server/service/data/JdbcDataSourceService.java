package net.identio.server.service.data;

import com.zaxxer.hikari.HikariDataSource;
import net.identio.server.model.DataSource;
import net.identio.server.service.configuration.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
public class JdbcDataSourceService {

    private HashMap<String, HikariDataSource> dataSources = new HashMap<>();

    @Autowired
    public JdbcDataSourceService(ConfigurationService configurationService) {

        for (DataSource dataSourceConfiguration : configurationService.getConfiguration().getDataSourcesConfiguration().getDataSources())
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
