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

package net.identio.server.service.oauth.infrastructure;

import liquibase.Contexts;
import liquibase.LabelExpression;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.exception.LiquibaseException;
import liquibase.resource.ClassLoaderResourceAccessor;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.service.data.DataService;
import net.identio.server.service.data.JdbcDataService;
import net.identio.server.service.oauth.OAuthConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.sql.Connection;
import java.sql.SQLException;

@Configuration
public class OAuthInfrastructureConfiguration implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(OAuthInfrastructureConfiguration.class);

    private static final String IN_MEMORY = "in-memory";
    private static final String JDBC = "jdbc";

    private String dsType;

    @Autowired
    private OAuthConfiguration config;

    @Autowired
    private DataService dataService;

    @Autowired
    private ApplicationContext context;

    @Autowired
    private JdbcDataService jdbcDataService;

    @Override
    public void afterPropertiesSet() throws InitializationException {

        this.dsType = config.getDataSource() != null ?
                dataService.getDataSourceConfiguration(config.getDataSource()).getType()
                : IN_MEMORY;

        switch (this.dsType) {

            case JDBC:
                initDataBaseSchema();
                break;

            case IN_MEMORY:
                break;

            default:
                LOG.error("Unsupported datasource type: {}", this.dsType);
                throw new InitializationException("Unsupported datasource type");
        }
    }

    @Bean
    public AuthorizationCodeRepository getAuthorizationCodeRepository() {

        AutowireCapableBeanFactory factory = context.getAutowireCapableBeanFactory();

        switch (this.dsType) {

            case JDBC:
                return factory.createBean(JdbcAuthorizationCodeRepository.class);
            default:
                return factory.createBean(InMemoryAuthorizationCodeRepository.class);
        }
    }

    @Bean
    public TokenRepository getRefreshTokenRepository() {
        AutowireCapableBeanFactory factory = context.getAutowireCapableBeanFactory();

        switch (this.dsType) {

            case JDBC:
                return factory.createBean(JdbcTokenRepository.class);
            default:
                return factory.createBean(InMemoryTokenRepository.class);
        }
    }

    private void initDataBaseSchema() throws InitializationException {

        try (Connection connection = jdbcDataService.getDataSource(config.getDataSource()).getConnection()) {

            // Find database and specify changelog tables in order to avoid destroying existing
            // liquibase configuration
            Database database = DatabaseFactory.getInstance().findCorrectDatabaseImplementation(new JdbcConnection(connection));

            database.setDatabaseChangeLogTableName("oauth_cl");
            database.setDatabaseChangeLogLockTableName("oauth_cl_lock");

            Liquibase liquibase = new Liquibase("db-schemas/oauth.yaml",
                    new ClassLoaderResourceAccessor(),
                    database);
            liquibase.update(new Contexts(), new LabelExpression());
        } catch (SQLException | LiquibaseException e) {
            throw new InitializationException("Error initializing authorization code database", e);
        }
    }
}
