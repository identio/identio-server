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

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.Result;
import net.identio.server.service.oauth.model.OAuthClient;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.utils.DecodeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.CustomClassLoaderConstructor;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.zip.DataFormatException;

@Service
public class FileOAuthClientRepository implements OAuthClientRepository {

    private static final Logger LOG = LoggerFactory.getLogger(FileOAuthClientRepository.class);

    private HashMap<String, OAuthClient> clients;

    @Autowired
    public FileOAuthClientRepository(ConfigurationService configurationService) throws InitializationException {


        clients = new HashMap<>();

        String clientFilePath = configurationService.getConfiguration().getoAuthServerConfiguration().getClientFile();

        if (clientFilePath == null) {
            return;
        }

        LOG.info("Initializing File OAUth Client Repository");

        try (FileInputStream is = new FileInputStream(clientFilePath)) {

            Yaml yaml = new Yaml(new CustomClassLoaderConstructor(OAuthClientFile.class,
                    Thread.currentThread().getContextClassLoader()));

            OAuthClientFile clientFile = (OAuthClientFile) yaml.load(is);

            for (OAuthClient client : clientFile.getoAuthClients()) {
                clients.put(client.getClientId(), client);
            }

        } catch (FileNotFoundException ex) {
            throw new InitializationException("OAUth Client Repository file not found", ex);
        } catch (IOException ex) {
            throw new InitializationException("Impossible to parse OAUth Client Repository file", ex);
        }

        LOG.info("* File OAUth Client Repository initialized");

    }

    @Override
    public OAuthClient getOAuthClientbyId(String clientId) {

        return clients.get(clientId);
    }

    public Result<OAuthClient> getClientFromAuthorization(String authorization) {

        if (authorization != null && authorization.startsWith("Basic ")) {

            try {
                String filteredAuthorization = new String(DecodeUtils.decode(authorization.substring(6), false));

                String[] credentials = filteredAuthorization.split(":");
                String clientId = credentials[0];
                String clientSecret = credentials[1];

                OAuthClient client = clients.get(clientId);

                if (client != null && client.getClientSecret().equals(clientSecret)) {
                    return Result.success(client);
                }

            } catch (IOException | DataFormatException e) {
                LOG.error("Error when decoding Authorization header");
            }
        }

        return Result.fail();
    }

}
