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
import net.identio.server.service.authentication.model.UserPasswordAuthentication;
import net.identio.server.service.oauth.OAuthConfiguration;
import net.identio.server.service.oauth.model.Client;
import net.identio.server.service.oauth.model.ResourceServer;
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
public class FileOAuthActorsRepository implements OAuthActorsRepository {

    private static final Logger LOG = LoggerFactory.getLogger(FileOAuthActorsRepository.class);

    private HashMap<String, Client> clients = new HashMap<>();

    private HashMap<String, ResourceServer> resourceServers = new HashMap<>();

    @Autowired
    public FileOAuthActorsRepository(OAuthConfiguration config) throws InitializationException {

        String actorsFilePath = config.getActorsFile();

        if (actorsFilePath == null)
            return;

        LOG.info("Initializing File OAUth Client Repository");

        try (FileInputStream is = new FileInputStream(actorsFilePath)) {

            Yaml yaml = new Yaml(new CustomClassLoaderConstructor(OAuthActorsFile.class,
                    Thread.currentThread().getContextClassLoader()));

            OAuthActorsFile actorsFile = (OAuthActorsFile) yaml.load(is);

            for (Client client : actorsFile.getClients()) {
                clients.put(client.getClientId(), client);
            }

            for (ResourceServer rs : actorsFile.getResourceServers()) {
                resourceServers.put(rs.getClientId(), rs);
            }

        } catch (FileNotFoundException ex) {
            throw new InitializationException("OAUth Client Repository file not found", ex);
        } catch (IOException ex) {
            throw new InitializationException("Impossible to parse OAUth Client Repository file", ex);
        }

        LOG.info("* File OAuth Client Repository initialized");
    }

    @Override
    public Client getClientbyId(String clientId) {

        return clients.get(clientId);
    }

    public Result<Client> getClientFromAuthorization(String authorization) {

        if (authorization != null && authorization.startsWith("Basic ")) {

            UserPasswordAuthentication credentials;
            try {
                credentials = getCredentialsFromAuthorization(authorization);
            } catch (IOException | DataFormatException e) {
                return Result.fail();
            }

            Client client = clients.get(credentials.getUserId());

            if (client != null && client.getClientSecret().equals(credentials.getPassword())) {
                return Result.success(client);
            }
        }

        return Result.fail();
    }

    public Result<ResourceServer> getResourceServerFromAuthorization(String authorization) {

        if (authorization != null && authorization.startsWith("Basic ")) {

            UserPasswordAuthentication credentials = null;
            try {
                credentials = getCredentialsFromAuthorization(authorization);
            } catch (IOException | DataFormatException e) {
                Result.fail();
            }

            ResourceServer rs = resourceServers.get(credentials.getUserId());

            if (rs != null && rs.getClientSecret().equals(credentials.getPassword())) {
                return Result.success(rs);
            }
        }

        return Result.fail();
    }

    private UserPasswordAuthentication getCredentialsFromAuthorization(String authorization) throws IOException, DataFormatException {

        String filteredAuthorization = new String(DecodeUtils.decode(authorization.substring(6), false));

        String[] credentials = filteredAuthorization.split(":");

        return new UserPasswordAuthentication(credentials[0], credentials[1]);
    }
}
