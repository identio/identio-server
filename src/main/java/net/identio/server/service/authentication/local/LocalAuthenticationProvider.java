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
package net.identio.server.service.authentication.local;

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.*;
import net.identio.server.service.authentication.AuthenticationProvider;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.model.*;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.transaction.model.TransactionData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.CustomClassLoaderConstructor;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

@Service
@Scope("singleton")
public class LocalAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(LocalAuthenticationProvider.class);

    private HashMap<String, LocalAuthMethod> fileAuthMethodsMap = new HashMap<>();

    private HashMap<LocalAuthMethod, HashMap<String, User>> globalUsersMap;

    @Autowired
    public LocalAuthenticationProvider(ConfigurationService configurationService,
                                       AuthenticationService authenticationService) throws InitializationException {

        List<LocalAuthMethod> authMethods = configurationService.getConfiguration().getAuthMethodConfiguration()
                .getLocalAuthMethods();

        if (authMethods == null)
            return;

        LOG.info("Initializing File Authentication Service");

        globalUsersMap = new HashMap<>();

        for (LocalAuthMethod fileAuthMethod : authMethods) {

            String userFilePath = fileAuthMethod.getUserFilePath();

            LOG.info("* Loading users from file: {}", userFilePath);

            try (FileInputStream is = new FileInputStream(userFilePath)) {

                Yaml yaml = new Yaml(new CustomClassLoaderConstructor(FileUserRepository.class,
                        Thread.currentThread().getContextClassLoader()));

                FileUserRepository repository = (FileUserRepository) yaml.load(is);

                // Index each entry by its userId
                HashMap<String, User> userMap = new HashMap<>();
                for (User user : repository.getUsers()) {
                    userMap.put(user.getUserId(), user);
                }
                globalUsersMap.put(fileAuthMethod, userMap);

            } catch (FileNotFoundException ex) {
                throw new InitializationException("Users file not found", ex);
            } catch (IOException ex) {
                throw new InitializationException("Impossible to parse users file", ex);
            }

            fileAuthMethodsMap.put(fileAuthMethod.getName(), fileAuthMethod);
        }

        register(authMethods, authenticationService);

        LOG.info("* File Authentication Service initialized");

    }

    public AuthenticationResult validate(AuthMethod authMethod, Authentication authentication,
                                         TransactionData transactionData) {

        LocalAuthMethod fileAuthMethod = (LocalAuthMethod) authMethod;
        UserPasswordAuthentication userPwAuthentication = (UserPasswordAuthentication) authentication;

        String userId = userPwAuthentication.getUserId();
        String password = userPwAuthentication.getPassword();

        if (userId == null || password == null) {
            LOG.error("UserId or password is empty");
            return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
                    .setErrorStatus(AuthenticationErrorStatus.INVALID_CREDENTIALS);
        }

        User user = globalUsersMap.get(fileAuthMethod).get(userId);

        if (user == null) {
            LOG.error("Unknown user: {}", userPwAuthentication.getUserId());
            return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
                    .setErrorStatus(AuthenticationErrorStatus.INVALID_CREDENTIALS);
        }

        String hashedPassword = user.getPassword();

        // If the password doesn't start with $, it is not hashed
        // $2a indicates a Bcrypt hash
        if (hashedPassword.charAt(0) != '$' && hashedPassword.equals(password)
                || hashedPassword.startsWith("$2a") && BCrypt.checkpw(password, hashedPassword)) {

            LOG.info("User {} successfully authenticated with {} method", user.getUserId(), fileAuthMethod.getName());

            return new AuthenticationResult().setStatus(AuthenticationResultStatus.SUCCESS).setUserId(userId)
                    .setAuthMethod(authMethod).setAuthLevel(authMethod.getAuthLevel());
        }

        LOG.info("Failed authentication for user {} with {} method", user.getUserId(), fileAuthMethod.getName());

        return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
                .setErrorStatus(AuthenticationErrorStatus.INVALID_CREDENTIALS);
    }

    private void register(List<LocalAuthMethod> authMethods, AuthenticationService authenticationService) {

        for (LocalAuthMethod authMethod : authMethods) {

            LOG.debug("* Registering authentication method {}", authMethod.getName());

            authenticationService.registerExplicit(authMethod, this);
        }
    }

    @Override
    public boolean accepts(Authentication authentication) {
        return authentication instanceof UserPasswordAuthentication;
    }
}
