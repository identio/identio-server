package net.identio.server.service.oauth.infrastructure;

import com.zaxxer.hikari.HikariDataSource;
import liquibase.Contexts;
import liquibase.LabelExpression;
import liquibase.Liquibase;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.exception.LiquibaseException;
import liquibase.resource.ClassLoaderResourceAccessor;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.DataSource;
import net.identio.server.service.oauth.exceptions.AuthorizationCodeCreationException;
import net.identio.server.service.oauth.model.AuthorizationCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;


public class JdbcAuthorizationCodeRepository implements AuthorizationCodeRepository {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcAuthorizationCodeRepository.class);
    private HikariDataSource ds;

    public JdbcAuthorizationCodeRepository(DataSource dataSourceConfiguration) throws InitializationException {

        initDataSource(dataSourceConfiguration);

        initDataBase();
    }

    private void initDataBase() throws InitializationException {
        Liquibase liquibase = null;
        try (Connection connection = this.ds.getConnection()) {
            liquibase = new Liquibase("db-schemas/oauth.yaml",
                    new ClassLoaderResourceAccessor(),
                    DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(connection)));
            liquibase.update(new Contexts(), new LabelExpression());

        } catch (SQLException | LiquibaseException e) {
            throw new InitializationException("Error initializing authorization code database", e);
        }
    }

    private void initDataSource(DataSource dataSourceConfiguration) {
        this.ds = new HikariDataSource();

        this.ds.setMaximumPoolSize(100);
        this.ds.setDriverClassName(dataSourceConfiguration.getDriver());
        this.ds.setJdbcUrl(dataSourceConfiguration.getUrl());
        this.ds.setUsername(dataSourceConfiguration.getUsername());
        this.ds.setPassword(dataSourceConfiguration.getPassword());
    }

    @Override
    public void save(AuthorizationCode code) throws AuthorizationCodeCreationException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("INSERT INTO authorization_code (code, client_id, redirect_uri, expiration_time) " +
                    "VALUES (?, ?, ?, ?);");

            creationStatement.setString(1, code.getCode());
            creationStatement.setString(2, code.getClientId());
            creationStatement.setString(3, code.getRedirectUrl());
            creationStatement.setTimestamp(4, new Timestamp(code.getExpirationTime().toDate().getTime()));

            creationStatement.executeUpdate();

        } catch (SQLException e) {
            String message = "Error when inserting authorization code in database";
            LOG.error("Error when inserting authorization code in database: {}", e.getMessage());
            throw new AuthorizationCodeCreationException(message, e);
        }
    }
}