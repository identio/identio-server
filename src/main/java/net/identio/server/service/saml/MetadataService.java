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
package net.identio.server.service.saml;

import net.identio.saml.*;
import net.identio.saml.exceptions.TechnicalException;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.IdentioConfiguration;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.utils.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Scope("singleton")
public class MetadataService {

    private static final Logger LOG = LoggerFactory.getLogger(MetadataService.class);

    // Private fields
    private Metadata idpMetadata;
    private HashMap<String, Validator> spValidators = new HashMap<>();
    private HashMap<String, Metadata> spMetadatas = new HashMap<>();

    private HashMap<String, HashMap<String, String>> loadedSpFiles = new HashMap<>();

    // Services
    private ConfigurationService configurationService;

    @Autowired
    public MetadataService(ConfigurationService configurationService) throws InitializationException {

        LOG.debug("Initialization of Metadata Service...");

        this.configurationService = configurationService;

        try {

            initIdpMetadata();

        } catch (TechnicalException ex) {
            throw new InitializationException("Could not initialize Metadata service", ex);
        }
    }

    private void initIdpMetadata() throws TechnicalException, InitializationException {

        IdentioConfiguration config = configurationService.getConfiguration();

        LOG.info("Loading SAML IDP metadata...");

        // Determine idp endpoint configuration
        ArrayList<Endpoint> idpEndpoints = new ArrayList<>();
        String idpPostUrl = config.getGlobalConfiguration().getPublicFqdn() + "/SAML2/SSO/POST";
        String idpRedirectUrl = config.getGlobalConfiguration().getPublicFqdn() + "/SAML2/SSO/Redirect";
        idpEndpoints.add(new Endpoint(1, SamlConstants.BINDING_HTTP_REDIRECT, idpRedirectUrl, true));
        idpEndpoints.add(new Endpoint(2, SamlConstants.BINDING_HTTP_POST, idpPostUrl, false));

        // Determine sp endpoint configuration
        ArrayList<Endpoint> spEndpoints = new ArrayList<>();
        String spPostUrl = config.getGlobalConfiguration().getPublicFqdn() + "/SAML2/ACS/POST";
        spEndpoints.add(new Endpoint(1, SamlConstants.BINDING_HTTP_POST, spPostUrl, true));

        // Extract certificate from provided P12
        ArrayList<X509Certificate> certs = new ArrayList<>();

        try (FileInputStream fis = new FileInputStream(config.getGlobalConfiguration().getSignatureKeystorePath())) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, config.getGlobalConfiguration().getSignatureKeystorePassword().toCharArray());

            Enumeration<String> aliases = ks.aliases();

            if (aliases == null || !aliases.hasMoreElements()) {
                throw new InitializationException("Keystore doesn't contain a certificate");
            }

            String alias = aliases.nextElement();

            certs.add((X509Certificate) (ks.getCertificate(alias)));

        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException ex) {
            throw new InitializationException("Could not initialize IDP Metadata", ex);
        }

        // Allow unsecure requests ?
        boolean wantRequestsSigned = !config.getSamlIdpConfiguration().isAllowUnsecureRequests();

        // Generate idp metadata
        IdpSsoDescriptor idpDescriptor = IdpSsoDescriptor.getInstance().setWantAuthnRequestsSigned(wantRequestsSigned)
                .setSsoEndpoints(idpEndpoints)
                .setNameIDFormat(Collections.singletonList(SamlConstants.NAMEID_UNSPECIFIED))
                .setSigningCertificates(certs);

        SpSsoDescriptor spDescriptor = SpSsoDescriptor.getInstance().setAuthentRequestSigned(true)
                .setAssertionConsumerService(spEndpoints)
                .setNameIDFormat(Collections.singletonList(SamlConstants.NAMEID_UNSPECIFIED))
                .setWantAssertionsSigned(false).setSigningCertificates(certs);

        idpMetadata = MetadataBuilder.getInstance()
                .setEntityID(config.getGlobalConfiguration().getPublicFqdn() + "/SAML2")
                .setOrganizationName(config.getSamlIdpConfiguration().getOrganizationName())
                .setOrganizationDisplayName(config.getSamlIdpConfiguration().getOrganizationDisplayName())
                .setOrganizationURL(config.getSamlIdpConfiguration().getOrganizationUrl())
                .setContactName(config.getSamlIdpConfiguration().getContactPersonSurname())
                .setContactEmail(config.getSamlIdpConfiguration().getContactPersonEmail())
                .setIdpSsoDescriptors(Collections.singletonList(idpDescriptor))
                .setSpSsoDescriptors(Collections.singletonList(spDescriptor)).build();

        LOG.info("* {}", idpMetadata.getEntityID());
    }

    private void loadMetadata(String filename) throws TechnicalException,
            NoSuchAlgorithmException, IOException {

        File file = new File(filename);

        Metadata spMetadata = MetadataBuilder.build(file);

        LOG.info("Loading SP Metadata {}: {}", spMetadata.getEntityID(), file.getAbsolutePath());

        if (spMetadatas.containsKey(spMetadata.getEntityID())) {
            LOG.error("* Metadata ignored: an existing metadata has the same Entity ID");
            return;
        }

        ArrayList<X509Certificate> certificates = new ArrayList<>();

        for (SpSsoDescriptor descriptor : spMetadata.getSpSsoDescriptors()) {
            certificates.addAll(descriptor.getSigningCertificates());
        }

        // Check if the metadatas is valid
        Validator validator = new Validator(certificates,
                configurationService.getConfiguration().getSamlIdpConfiguration().isCertificateCheckEnabled());

        spValidators.put(spMetadata.getEntityID(), validator);
        spMetadatas.put(spMetadata.getEntityID(), spMetadata);

        HashMap<String, String> fileProperties = new HashMap<>();

        fileProperties.put("issuer", spMetadata.getEntityID());
        fileProperties.put("hash", FileUtils.getFileHash(filename));

        loadedSpFiles.put(filename, fileProperties);
    }

    private void unloadMetadata(String filename) {

        LOG.info("Unloading SAML SP metadata: {}", filename);

        HashMap<String, String> fileProperties = loadedSpFiles.get(filename);

        String issuer = fileProperties.get("issuer");

        spMetadatas.remove(issuer);
        spValidators.remove(issuer);
    }

    private void checkUpdatedMetadata(String filename)
            throws NoSuchAlgorithmException, IOException, TechnicalException {

        LOG.debug("Check update of SAML SP metadata: {}", filename);

        HashMap<String, String> fileProperties = loadedSpFiles.get(filename);

        String hash = fileProperties.get("hash");

        // Check if the metadata is modified
        if (!FileUtils.getFileHash(filename).equals(hash)) {
            unloadMetadata(filename);
            loadMetadata(filename);
        }
    }

    @Scheduled(fixedDelayString = "60000")
    public void refreshSpMetadatas() {

        LOG.debug("Refreshing SAML SP metadata...");

        IdentioConfiguration config = configurationService.getConfiguration();

        String spMetadataDirectory = config.getSamlIdpConfiguration().getSpMetadataDirectory();
        List<String> spFiles = new ArrayList<>();

        // Build the SP metadata
        File[] files = new File(spMetadataDirectory).listFiles();

        if (files != null) {
            spFiles = Stream.of(files)
                    .filter(x -> x.isFile() && x.getName().endsWith(".xml")).map(File::getAbsolutePath)
                    .collect(Collectors.toList());
        }

        List<String> newFileNames = new ArrayList<>(spFiles);
        newFileNames.removeAll(loadedSpFiles.keySet());

        List<String> removedFileNames = new ArrayList<>(loadedSpFiles.keySet());
        removedFileNames.removeAll(spFiles);

        List<String> existingFileNames = new ArrayList<>(loadedSpFiles.keySet());
        existingFileNames.retainAll(spFiles);

        try {
            for (String filename : newFileNames) {
                loadMetadata(filename);
            }

            for (String filename : removedFileNames) {
                unloadMetadata(filename);
            }

            for (String filename : existingFileNames) {
                checkUpdatedMetadata(filename);
            }

        } catch (NoSuchAlgorithmException | TechnicalException | IOException e) {
            LOG.error("An error occured when refreshing SP metadatas: {}", e.getMessage());
            LOG.debug("* Detailed exception:", e);
        }
    }

    public Validator getSpValidator(String issuer) {
        return spValidators.get(issuer);
    }

    public Metadata getIdpMetadata() {
        return idpMetadata;
    }

    public Metadata getSpMetadata(String issuer) {
        return spMetadatas.get(issuer);
    }
}