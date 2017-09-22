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
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeCreationException;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeDeleteException;
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeFetchException;
import net.identio.server.service.oauth.model.AuthorizationCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.Optional;


public class JdbcAuthorizationCodeRepository implements AuthorizationCodeRepository {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcAuthorizationCodeRepository.class);
    private HikariDataSource ds;

    public JdbcAuthorizationCodeRepository(DataSource dataSourceConfiguration) throws InitializationException {

        initDataSource(dataSourceConfiguration);

        initDataBase();
    }

    private void initDataBase() throws InitializationException {

        try (Connection connection = this.ds.getConnection()) {

            Liquibase liquibase = new Liquibase("db-schemas/oauth.yaml",
                    new ClassLoaderResourceAccessor(),
                    DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(connection)));
            liquibase.update(new Contexts(), new LabelExpression());

        } catch (SQLException | LiquibaseException e) {
            throw new InitializationException("Error initializing authorization code database", e);
        }
    }

    private void initDataSource(DataSource dataSourceConfiguration) {
        this.ds = new HikariDataSource();

        this.ds.setMaximumPoolSize(10);
        this.ds.setDriverClassName(dataSourceConfiguration.getDriver());
        this.ds.setJdbcUrl(dataSourceConfiguration.getUrl());
        this.ds.setUsername(dataSourceConfiguration.getUsername());
        this.ds.setPassword(dataSourceConfiguration.getPassword());
    }

    @Override
    public void save(AuthorizationCode code) throws AuthorizationCodeCreationException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("INSERT INTO authorization_code (code, client_id, redirect_uri, expiration_time, scope, user_id) " +
                    "VALUES (?, ?, ?, ?, ?, ?);");

            creationStatement.setString(1, code.getCode());
            creationStatement.setString(2, code.getClientId());
            creationStatement.setString(3, code.getRedirectUrl());
            creationStatement.setLong(4, code.getExpirationTime());
            creationStatement.setString(5, code.getScope());
            creationStatement.setString(6, code.getUserId());

            creationStatement.executeUpdate();

        } catch (SQLException e) {
            LOG.error("Error when inserting authorization code {} in database: {}", code.getCode(), e.getMessage());
            throw new AuthorizationCodeCreationException(e);
        }
    }

    @Override
    public Optional<AuthorizationCode> getAuthorizationCodeByValue(String code) throws AuthorizationCodeFetchException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("SELECT * FROM authorization_code WHERE code = ?;");

            creationStatement.setString(1, code);

            ResultSet rs = creationStatement.executeQuery();

            // Fetch
            if (!rs.first()) {
                return Optional.empty();
            } else {
                return Optional.of(
                        new AuthorizationCode().setCode(code)
                        .setRedirectUrl(rs.getString("redirect_uri"))
                        .setClientId(rs.getString("client_id"))
                        .setExpirationTime(rs.getLong("expiration_time"))
                        .setScope(rs.getString("scope"))
                        .setUserId(rs.getString("user_id"))
                );
            }

        } catch (SQLException e) {
            LOG.error("Error when fetching authorization code {} in database: {}", code, e.getMessage());
            throw new AuthorizationCodeFetchException(e);
        }
    }

    @Override
    public void delete(AuthorizationCode code) throws AuthorizationCodeDeleteException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("DELETE FROM authorization_code WHERE code = ?;");

            creationStatement.setString(1, code.getCode());

            creationStatement.executeUpdate();

        } catch (SQLException e) {
            LOG.error("Error when inserting authorization code {} in database: {}", code.getCode(), e.getMessage());
            throw new AuthorizationCodeDeleteException(e);
        }
    }
}