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
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.data.JdbcDataSourceService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.Connection;
import java.sql.SQLException;

@Configuration
public class OAuthInfrastructureConfiguration implements InitializingBean {

    private String dsType;
    private HikariDataSource jdbcDs;

    @Autowired
    private ConfigurationService configurationService;

    @Autowired
    private JdbcDataSourceService jdbcDataSourceService;

    @Override
    public void afterPropertiesSet() throws InitializationException {

        DataSource dataSourceConfiguration = configurationService.getConfiguration().getoAuthServerConfiguration().getDataSource();

        this.dsType = dataSourceConfiguration.getType();

        if ("jdbc".equals(this.dsType)) {

            this.jdbcDs = jdbcDataSourceService.getDataSource(dataSourceConfiguration.getName());
            initDataBaseSchema();
        }
    }

    @Bean
    public AuthorizationCodeRepository getAuthorizationCodeRepository() throws InitializationException {

        if ("jdbc".equals(this.dsType)) return new JdbcAuthorizationCodeRepository(jdbcDs);

        return new InMemoryAuthorizationCodeRepository();
    }

    private void initDataBaseSchema() throws InitializationException {

        try (Connection connection = this.jdbcDs.getConnection()) {

            Liquibase liquibase = new Liquibase("db-schemas/oauth.yaml",
                    new ClassLoaderResourceAccessor(),
                    DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(connection)));
            liquibase.update(new Contexts(), new LabelExpression());

        } catch (SQLException | LiquibaseException e) {
            throw new InitializationException("Error initializing authorization code database", e);
        }
    }
}
