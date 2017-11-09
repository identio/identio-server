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
package net.identio.server.boot;

import net.identio.server.service.authentication.x509.X509AuthMethod;
import net.identio.server.service.authentication.x509.X509AuthenticationProvider;
import net.identio.server.utils.SecurityUtils;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11Protocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatConnectorCustomizer;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Configuration
public class BootCustomizationBean {

    private static final Logger LOG = LoggerFactory.getLogger(BootCustomizationBean.class);

    @Autowired
    private GlobalConfiguration config;

    @Autowired
    private X509AuthenticationProvider x509AuthenticationProvider;

    @Value("${identio.work.directory}")
    private String workDirectory;

    @Bean
    public EmbeddedServletContainerFactory servletContainer() {

        TomcatEmbeddedServletContainerFactory factory = new TomcatEmbeddedServletContainerFactory();
        factory.setPort(config.getPort());

        factory.setSessionTimeout(5, TimeUnit.MINUTES);

        factory.addConnectorCustomizers((TomcatConnectorCustomizer) connector -> {

            AbstractHttp11Protocol<?> httpProtocol = (AbstractHttp11Protocol<?>) connector.getProtocolHandler();
            httpProtocol.setCompression("on");
            httpProtocol.setMaxThreads(150);

            if (config.isSecure()) {

                connector.setSecure(true);
                connector.setScheme("https");
                connector.setAttribute("keystoreFile", "file:///"
                        + config.getSslKeystorePath());
                connector.setAttribute("keystorePass",
                        config.getSslKeystorePassword());
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
        });
        return factory;
    }

    private void configureTlsClientAuth(Connector connector) {

        List<X509AuthMethod> x509methods = x509AuthenticationProvider.getConfiguredAuthMethods();

        if (x509methods.size() > 0) {

            try (FileOutputStream fos = new FileOutputStream(
                    workDirectory + "/identio-trust.jks")) {

                // Tomcat is finicky about the format of paths, and especially doesn't like '\' on windows
                // So here comes this beautiful hack...
                String trustPath = Paths.get(workDirectory + "/identio-trust.jks").toString()
                        .replaceAll("\\\\", "/");

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
                        "file:" + trustPath);
                connector.setAttribute("truststorePass", trustPassword);
                connector.setAttribute("truststoreType", "JKS");

            } catch (KeyStoreException | NoSuchAlgorithmException e) {
                LOG.error("Impossible to create temporary key store. Client authentication certs NOT loaded");
                LOG.debug("* Detailed Stacktrace:", e);
            } catch (CertificateException | IOException e) {
                LOG.error("Error when parsing client authentication certificate");
                LOG.debug("* Detailed Stacktrace:", e);
            }
        }
    }

}