package net.identio.server.service.oauth.infrastructure;

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.DataSource;
import net.identio.server.service.configuration.ConfigurationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthorizationCodeRepositoryConfiguration {

    @Autowired
    private ConfigurationService configurationService;

    @Bean
    public AuthorizationCodeRepository getAuthorizationCodeRepository() throws InitializationException {

        DataSource ds = configurationService.getConfiguration().getoAuthServerConfiguration().getDataSource();

        if (ds == null) return new InMemoryAuthorizationCodeRepository();

        if ("jdbc".equals(ds.getType())) {
            return new JdbcAuthorizationCodeRepository(ds);
        }

        return new InMemoryAuthorizationCodeRepository();
    }

}
