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
package net.identio.server.boot;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import net.identio.server.model.X509AuthMethod;
import net.identio.server.service.authentication.x509.X509AuthenticationProvider;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.utils.SecurityUtils;

@Configuration
public class BootCustomizationBean {

	private static final Logger LOG = LoggerFactory.getLogger(BootCustomizationBean.class);

	@Autowired
	private ConfigurationService configurationService;

	@Autowired
	private X509AuthenticationProvider x509AuthenticationProvider;

	@Bean
	public EmbeddedServletContainerFactory servletContainer() {

		TomcatEmbeddedServletContainerFactory factory = new TomcatEmbeddedServletContainerFactory();
		factory.setPort(configurationService.getConfiguration().getGlobalConfiguration().getPort());

		factory.setSessionTimeout(5, TimeUnit.MINUTES);

		factory.addConnectorCustomizers(new TomcatConnectorCustomizer() {
			@Override
			public void customize(Connector connector) {

				AbstractHttp11Protocol<?> httpProtocol = (AbstractHttp11Protocol<?>) connector.getProtocolHandler();
				httpProtocol.setCompression("on");
				httpProtocol.setMaxThreads(150);

				if (configurationService.getConfiguration().getGlobalConfiguration().isSecure()) {

					connector.setSecure(true);
					connector.setScheme("https");
					connector.setAttribute("keystoreFile", "file:///"
							+ configurationService.getConfiguration().getGlobalConfiguration().getSslKeystorePath());
					connector.setAttribute("keystorePass",
							configurationService.getConfiguration().getGlobalConfiguration().getSslKeystorePassword());
					connector.setAttribute("keystoreType", "PKCS12");
					connector.setAttribute("keyAlias", "1");
					connector.setAttribute("sslProtocol", "TLSv1.2");
					connector.setAttribute("sslEnabledProtocols", "+TLSv1.1,+TLSv1.2");
					connector.setAttribute("SSLEnabled", true);
					connector.setAttribute("ciphers",
							"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA");
					connector.setAttribute("server", "Ident.io Server");
					configureTlsClientAuth(connector);
				}
			}
		});
		return factory;
	}

	private void configureTlsClientAuth(Connector connector) {

		List<X509AuthMethod> x509methods = configurationService.getConfiguration().getAuthMethodConfiguration()
				.getX509AuthMethods();

		if (x509methods != null) {

			try (FileOutputStream fos = new FileOutputStream(
					configurationService.getConfiguration().getGlobalConfiguration().getWorkDirectory()
							+ "/identio-trust.jks")) {

				KeyStore ks = KeyStore.getInstance("JKS");
				ks.load(null, null);

				for (X509Certificate cert : x509AuthenticationProvider.getServerTrusts()) {
					SecurityUtils.addCertificateToKeyStore(ks, cert, UUID.randomUUID().toString());
				}

				// As the keystore contains only public certs, the password here
				// is not relevant
				String trustPassword = UUID.randomUUID().toString();
				ks.store(fos, trustPassword.toCharArray());

				connector.setAttribute("clientAuth", "want");
				connector.setAttribute("truststoreFile",
						"file:///" + configurationService.getConfiguration().getGlobalConfiguration().getWorkDirectory()
								+ "/identio-trust.jks");
				connector.setAttribute("truststorePass", trustPassword);
				connector.setAttribute("truststoreType", "JKS");

			} catch (KeyStoreException | NoSuchAlgorithmException e) {
				LOG.error("Impossible to create temporary key store. Client authentication certs NOT loaded");
				LOG.debug("* Detailed Stacktrace:", e);
			} catch (CertificateException e) {
				LOG.error("Error when parsing client authentication certificate");
				LOG.debug("* Detailed Stacktrace:", e);
			} catch (IOException e) {
				LOG.error("Error when parsing client authentication certificate");
				LOG.debug("* Detailed Stacktrace:", e);
			}
		}
	}

}