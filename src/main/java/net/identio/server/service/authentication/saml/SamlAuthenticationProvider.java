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
package net.identio.server.service.authentication.saml;

import net.identio.saml.*;
import net.identio.saml.exceptions.*;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.model.*;
import net.identio.server.service.authentication.AuthenticationProvider;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.model.*;
import net.identio.server.service.orchestration.model.SamlAuthRequest;
import net.identio.server.service.saml.MetadataService;
import net.identio.server.service.saml.SamlService;
import net.identio.server.utils.DecodeUtils;
import net.identio.server.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

@Service
public class SamlAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(SamlAuthenticationProvider.class);

    private HashMap<String, Validator> remoteIdpValidators;
    private HashMap<String, Metadata> remoteIdpMetadatasByName;

    @Autowired
    private SamlService samlService;

    @Autowired
    private MetadataService metadataService;

    @Autowired
    public SamlAuthenticationProvider(SamlAuthenticationProviderConfiguration config,
                                      AuthenticationService authenticationService) throws InitializationException {

        LOG.debug("Initialization of Metadata Service...");

        try {

            initRemoteIdpMetadata(config);

            register(config.getAuthMethods(),
                    authenticationService);

        } catch (TechnicalException ex) {
            throw new InitializationException("Could not initialize Metadata service", ex);
        }
    }

    private void initRemoteIdpMetadata(SamlAuthenticationProviderConfiguration config) throws TechnicalException {

        List<SamlAuthMethod> samlAuthMethods = config.getAuthMethods();

        if (samlAuthMethods == null || samlAuthMethods.size() == 0) return;

        LOG.info("Loading Remote IDP metadata...");

        remoteIdpValidators = new HashMap<>();
        remoteIdpMetadatasByName = new HashMap<>();

        for (SamlAuthMethod authMethod : samlAuthMethods) {

            Metadata remoteIdpMetadata = MetadataBuilder.build(new File(authMethod.getMetadata()));
            LOG.info("* {}: {}", remoteIdpMetadata.getEntityID(), authMethod.getMetadata());

            ArrayList<X509Certificate> certificates = new ArrayList<>();

            for (IdpSsoDescriptor descriptor : remoteIdpMetadata.getIdpSsoDescriptors()) {
                certificates.addAll(descriptor.getSigningCertificates());
            }

            // Check if the metadatas is valid
            Validator validator = new Validator(certificates, authMethod.isCertificateCheckEnabled());

            remoteIdpValidators.put(authMethod.getName(), validator);
            remoteIdpMetadatasByName.put(authMethod.getName(), remoteIdpMetadata);
        }
    }

    public Result<SamlAuthRequest> initRequest(SamlAuthMethod authMethod, ArrayList<AuthLevel> targetAuthLevels,
                                       String transactionId) {

        Metadata remoteMetadata = remoteIdpMetadatasByName.get(authMethod.getName());

        ArrayList<String> requestedAuthContext = new ArrayList<>();

        HashMap<AuthLevel, String> outMap = authMethod.getSamlAuthMap().getOut();

        // Find target auth levels
        for (AuthLevel targetAuthLevel : targetAuthLevels) {

            String urn = outMap.get(targetAuthLevel);

            if (urn != null && !requestedAuthContext.contains(urn)) {
                requestedAuthContext.add(0, urn);
            }

        }

        return samlService.generateAuthentRequest(remoteMetadata, requestedAuthContext, SamlConstants.COMPARISON_EXACT,
                transactionId, authMethod.getName());
    }

    public AuthenticationResult validate(AuthMethod authMethod, Authentication authentication) {

        LOG.info("Validating SAML response from proxy IDP");

        SamlAuthentication samlAuthentication = (SamlAuthentication) authentication;

        try {
            Result<byte[]> decodedSamlResponse = DecodeUtils.decode(samlAuthentication.getResponse(), false);

            if (!decodedSamlResponse.isSuccess())
                return AuthenticationResult.fail(AuthenticationErrorStatus.TECHNICAL_ERROR);

            SamlAuthMethod samlAuthMethod = (SamlAuthMethod) authMethod;

            Metadata idpMetadata = metadataService.getIdpMetadata();
            Validator remoteValidator = remoteIdpValidators.get(samlAuthMethod.getName());

            AuthentResponse response = AuthentResponseBuilder.getInstance().build(new String(decodedSamlResponse.get()));
            Assertion assertion = response.getAssertion();

            // Verify the status of the response
            String responseStatusCode = response.getStatusCode();

            if (!SamlConstants.STATUS_SUCCESS.equals(responseStatusCode)) {
                LOG.error("* Authentication rejected by proxy IDP");
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_REJECTED);
            }

            // Verify the presence of a SAML Assertion
            if (assertion == null) {
                LOG.error("* No assertion found in response");
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            // Check inResponseTo attribute coherence
            if (!samlAuthentication.getRequestId().equals(assertion.getInResponseTo())) {
                LOG.error("* InResponseTo ID doesn't match request ID");
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            // Check that the recipient of the assertion is the IDP
            if (assertion.getAudienceRestriction() == null
                    || !assertion.getAudienceRestriction().equals(idpMetadata.getEntityID())) {
                LOG.error("* Audience in assertion doesn't match IDP EntityID");
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            // Check recipient and destination
            boolean validation = false;
            String recipient = assertion.getRecipient();
            String destination = response.getDestination();

            if (recipient == null) {
                LOG.error("* No recipient specified in assertion");
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            if (destination == null) {
                LOG.error("* No destination specified in response");
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            for (Endpoint endpoint : idpMetadata.getSpSsoDescriptors().get(0).getAssertionConsumerServices()) {
                String location = endpoint.getLocation();

                if (location.equals(recipient) && location.equals(destination)) {
                    validation = true;
                }
            }

            if (!validation) {
                LOG.error("* Recipient or destination in response doesn't match an IDP endpoint");
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            // Check assertion time conditions
            try {
                remoteValidator.checkConditions(assertion);
            } catch (InvalidAssertionException ex) {
                LOG.error("* Conditions in the assertion are not valid: {}", ex.getMessage());
                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            try {
                remoteValidator.validate(response);

            } catch (UnsignedSAMLObjectException | NoSuchAlgorithmException | UntrustedSignerException
                    | InvalidSignatureException ex) {

                LOG.error("* Response is invalid: {}", ex.getMessage());
                LOG.debug("* Detailed stacktrace:", ex);

                return AuthenticationResult.fail(AuthenticationErrorStatus.AUTH_SAML_INVALID_RESPONSE);
            }

            // If the assertion is valid
            LOG.info("* Response is valid");

            // Mapping the authentication level
            AuthLevel authLevel = samlAuthMethod.getSamlAuthMap().getIn().get(assertion.getAuthnContext());

            return AuthenticationResult.success()
                    .setUserId(assertion.getSubjectNameID()).setAuthMethod(samlAuthMethod).setAuthLevel(authLevel);

        } catch (TechnicalException
                | InvalidAuthentResponseException ex) {
            LOG.error("* Error when parsing SAML Response: {}", ex.getMessage());
        }
        return AuthenticationResult.fail(AuthenticationErrorStatus.TECHNICAL_ERROR);
    }

    private void register(List<SamlAuthMethod> authMethods, AuthenticationService authenticationService) {

        if (authMethods == null) {
            return;
        }

        for (SamlAuthMethod authMethod : authMethods) {

            LOG.debug("* Registering authentication method {}", authMethod.getName());

            authenticationService.registerExplicit(authMethod, this);
        }
    }

    @Override
    public boolean accepts(Authentication authentication) {
        return authentication instanceof SamlAuthentication;
    }

    public ProxyAuthContext getContextFromRelayState(String relayState) {

        String decryptedRelayState = SecurityUtils.decrypt(relayState);
        String[] contextElements = decryptedRelayState.split(":");

        return new ProxyAuthContext().setTransactionId(contextElements[0]).setAuthMethodName(contextElements[1]).setRequestId(contextElements[2]);
    }
}
