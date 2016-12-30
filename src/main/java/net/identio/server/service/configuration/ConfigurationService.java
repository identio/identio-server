/*
 This file is part of Ident.io

 Ident.io - A flexible authentication server
 Copyright (C) Loeiz TANGUY

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.identio.server.service.configuration;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Paths;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.CustomClassLoaderConstructor;

import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.IdentioConfiguration;

@Service
public class ConfigurationService {

	private static final Logger LOG = LoggerFactory.getLogger(ConfigurationService.class);

	private IdentioConfiguration configuration;
	private String configFile;
	private String publicFqdn;
	
	@Autowired
	public ConfigurationService(@Value("${identio.config}") String configFile, @Value("${identio.public.fqdn}") String publicFqdn) throws InitializationException {

		if (publicFqdn == null) {
			throw new InitializationException("No public FQDN specified");
		}
		
		this.configFile = configFile;
		this.publicFqdn = publicFqdn;
		
		LOG.debug("Loading configuration file: {}", configFile);

		try (FileInputStream is = new FileInputStream(configFile)) {

			Yaml yaml = new Yaml(new CustomClassLoaderConstructor(IdentioConfiguration.class,
					Thread.currentThread().getContextClassLoader()));

			// convert json string to object
			configuration = (IdentioConfiguration) yaml.load(is);

			setDefaultValues();

		} catch (FileNotFoundException ex) {
			throw new InitializationException("Configuration file not found", ex);
		} catch (IOException ex) {
			throw new InitializationException("Impossible to parse configuration file", ex);
		}
	}

	public String getPublicFqdn() {
		return publicFqdn;
	}
	
	public IdentioConfiguration getConfiguration() {
		return configuration;
	}

	private void setDefaultValues() throws IOException {

		String configDirectoryPath = Paths.get(configFile).getParent().toAbsolutePath().normalize().toString();
		String home = Paths.get(configDirectoryPath).getParent().toString();

		// Global configuration default values

		if (configuration.getGlobalConfiguration().getSslKeystorePassword() == null) {
			configuration.getGlobalConfiguration().setSslKeystorePassword("password");
		}

		if (configuration.getGlobalConfiguration().getSslKeystorePath() == null) {
			configuration.getGlobalConfiguration()
					.setSslKeystorePath(Paths.get(configDirectoryPath, "ssl-certificate.p12").toString());
		}

		if (configuration.getGlobalConfiguration().getPort() == 0) {
			if (configuration.getGlobalConfiguration().isSecure()) {
				configuration.getGlobalConfiguration().setPort(10443);
			} else {
				configuration.getGlobalConfiguration().setPort(10080);
			}
		}

		if (configuration.getGlobalConfiguration().getSignatureKeystorePath() == null) {
			configuration.getGlobalConfiguration()
					.setSignatureKeystorePath(Paths.get(configDirectoryPath, "default-sign-certificate.p12").toString());
		}

		if (configuration.getGlobalConfiguration().getSslKeystorePassword() == null) {
			configuration.getGlobalConfiguration().setSslKeystorePassword("password");
		}
		
		if (configuration.getGlobalConfiguration().getWorkDirectory() == null) {
			configuration.getGlobalConfiguration().setWorkDirectory(Paths.get(configDirectoryPath, "work").toString());
		}

		if (configuration.getGlobalConfiguration().getStaticResourcesPath() == null) {
			configuration.getGlobalConfiguration().setStaticResourcesPath(Paths.get(home, "ui/").toString());
		}

		// SAML IDP configuration default values
		
		if (configuration.getSamlIdpConfiguration().getTokenValidityLength() == 0) {
			configuration.getSamlIdpConfiguration().setTokenValidityLength(3);
		}
		
		if (configuration.getSamlIdpConfiguration().getSpMetadataDirectory() == null) {
			configuration.getSamlIdpConfiguration()
					.setSpMetadataDirectory(Paths.get(configDirectoryPath, "trusted-sp").toString());
		}

		// File authentication method
		if (configuration.getAuthMethodConfiguration().getLocalAuthMethods() != null) {
			configuration.getAuthMethodConfiguration().getLocalAuthMethods().stream()
					.filter(x -> x.getUserFilePath() == null)
					.forEach(x -> x.setUserFilePath(Paths.get(configDirectoryPath, "users.yml").toString()));
		}

	}
}
