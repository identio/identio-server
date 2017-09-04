package net.identio.server.service.oauth.infrastructure;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import net.identio.server.model.DataSource;
import org.joda.time.DateTime;

import java.sql.Connection;
import java.sql.SQLException;

public class JdbcAuthorizationCodeRepository implements AuthorizationCodeRepository {

    private HikariDataSource ds;

    public JdbcAuthorizationCodeRepository(DataSource dataSourceConfiguration) {

        ds = new HikariDataSource();

        ds.setMaximumPoolSize(100);
        ds.setDriverClassName(dataSourceConfiguration.getDriver());
        ds.setJdbcUrl(dataSourceConfiguration.getUrl());
        ds.setUsername(dataSourceConfiguration.getUsername());
        ds.setPassword(dataSourceConfiguration.getPassword());
    }

    @Override
    public boolean save(String code, String clientId, String redirectUrl, DateTime expirationTime) {
        return false;
    }
}
