package net.identio.server.service.oauth.infrastructure;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.CustomClassLoaderConstructor;

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.OAuthClient;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.oauth.OAuthClientRepository;

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
	public OAuthClient getOAuthClientbyId(String cliendId) {
		
		return clients.get(cliendId);
	}

}
