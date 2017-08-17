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
import net.identio.saml.exceptions.*;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.exceptions.SamlException;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.model.*;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.authpolicy.model.AuthPolicyDecision;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import net.identio.server.service.orchestration.model.RequestParsingStatus;
import net.identio.server.service.orchestration.model.ResponseData;
import net.identio.server.service.orchestration.model.SamlAuthRequestGenerationResult;
import net.identio.server.utils.DecodeUtils;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.zip.DataFormatException;

@Service
@Scope("singleton")
public class SamlService {

    private static final Logger LOG = LoggerFactory.getLogger(SamlService.class);

    private Signer signer;

    private MetadataService metadataService;

    private ConfigurationService configurationService;

    private AuthPolicyService authPolicyService;

    @Autowired
    public SamlService(ConfigurationService configurationService, MetadataService metadataService,
                       AuthPolicyService authPolicyService) throws InitializationException {

        this.configurationService = configurationService;
        this.metadataService = metadataService;
        this.authPolicyService = authPolicyService;

        try {

            initSigner(configurationService.getConfiguration());
        } catch (TechnicalException ex) {
            String message = "Could not initialize SamlService";
            LOG.error("{}: {}", message, ex.getMessage());
            throw new InitializationException(message, ex);
        }
    }

    private void initSigner(IdentioConfiguration config) throws TechnicalException {

        String keystoreFile = config.getGlobalConfiguration().getSignatureKeystorePath();
        String keystorePassword = config.getGlobalConfiguration().getSignatureKeystorePassword();
        boolean isCertificateCheckEnabled = config.getSamlIdpConfiguration().isCertificateCheckEnabled();

        LOG.debug("Initializing SAML signer...");

        signer = new Signer(keystoreFile, keystorePassword, isCertificateCheckEnabled,
                SamlConstants.SIGNATURE_ALG_RSA_SHA256);
    }

    public RequestParsingInfo validateAuthentRequest(SamlInboundRequest request) {

        LOG.debug("Starting SAML Authentication Request orchestration...");

        RequestParsingInfo result = new RequestParsingInfo();

        result.setProtocolType(ProtocolType.SAML);

        // Parse the authentication request
        AuthentRequest ar;
        try {
            ar = AuthentRequestBuilder.getInstance().build(request.getSerializedRequest(), false);
        } catch (TechnicalException | InvalidRequestException e1) {
            LOG.error("Impossible to build AuthentRequest");
            return result.setStatus(RequestParsingStatus.FATAL_ERROR)
                    .setErrorStatus(SamlConstants.STATUS_REQUEST_UNSUPPORTED);
        }

        // Extract interesting values
        String requestIssuer = ar.getIssuer();

        ArrayList<String> requestedAuthnContext = ar.getRequestedAuthnContext();
        String comparison = ar.getAuthnContextComparison();
        boolean forceAuthn = ar.isForceAuthn();
        String requestId = ar.getId();
        Endpoint destinationEndpoint = findResponseEndpoint(ar);

        if (destinationEndpoint == null) {
            LOG.error("No suitable response endpoint found");
            return result.setStatus(RequestParsingStatus.FATAL_ERROR)
                    .setErrorStatus(SamlConstants.STATUS_UNSUPPORTED_BINDING);
        }

        result.setRequestId(requestId).setSourceApplicationName(requestIssuer).setAuthLevelComparison(comparison)
                .setForceAuthentication(forceAuthn).setProtocolType(ProtocolType.SAML)
                .setRelayState(request.getRelayState()).setResponseUrl(destinationEndpoint.getLocation());

        // Extract the requested authentication level, if any
        if (requestedAuthnContext != null) {
            ArrayList<AuthLevel> requestedAuthLevels = new ArrayList<>();

            for (String authLevelString : requestedAuthnContext) {
                try {
                    requestedAuthLevels.add(authPolicyService.getAuthLevelByUrn(authLevelString));
                } catch (UnknownAuthLevelException e) {
                    return result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                            .setErrorStatus(SamlConstants.STATUS_NO_AUTHN_CONTEXT);
                }
            }

            result.setRequestedAuthLevels(requestedAuthLevels);
        }

        LOG.debug("* Request Issuer: {} ", requestIssuer);
        LOG.debug("* Request ID: {}", requestId);
        if (LOG.isDebugEnabled() && requestedAuthnContext != null) {
            for (String s : requestedAuthnContext) {
                LOG.debug("* Requested authentication context : {}", s);
            }
        }
        LOG.debug("* Comparison: {}", comparison);
        LOG.debug("* Request forcing reauthentication: {}", forceAuthn);

        // The request issuer field cannot be null
        if (requestIssuer == null) {
            LOG.error("Request Issuer is empty");
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                    .setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
        }

        // Check if the issuer is registered
        Validator validator = metadataService.getSpValidator(requestIssuer);
        if (validator == null) {
            LOG.error("No validator found for issuer {}", requestIssuer);
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                    .setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
        }

        // Check that we are the recipient of the Authentication Request
        String destination = ar.getDestination();

        if (destination == null) {
            LOG.error("No destination specified in request");
            return result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                    .setErrorStatus(SamlConstants.STATUS_UNSUPPORTED_BINDING);

        } else {

            boolean endpointFound = false;

            for (IdpSsoDescriptor descriptor : metadataService.getIdpMetadata().getIdpSsoDescriptors()) {
                for (Endpoint endpoint : descriptor.getSsoEndpoints()) {
                    if (endpoint.getLocation().equals(destination)
                            && request.getBinding().equals(endpoint.getBinding())) {
                        endpointFound = true;
                    }
                }
            }
            if (!endpointFound) {
                LOG.error("The request destination doesn't match server SAML endpoints");
                return result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                        .setErrorStatus(SamlConstants.STATUS_UNSUPPORTED_BINDING);
            }
        }

        // Check the signature and the conditions
        if (SamlConstants.BINDING_HTTP_REDIRECT.equals(request.getBinding())
                && !validateRedirectRequest(validator, request, result)
                || !validatePostRequest(validator, ar, result)) {
            return result;
        }

        LOG.debug("* Request is valid");
        result.setStatus(RequestParsingStatus.OK);

        return result;

    }

    private boolean validateRedirectRequest(Validator validator, SamlInboundRequest request,
                                            RequestParsingInfo result) {

        LOG.debug("Validate query parameters of HTTP-Redirect Binding");

        byte[] signature;
        try {
            signature = DecodeUtils.decode(request.getSignatureValue(), false);
        } catch (Base64DecodingException | IOException | DataFormatException e) {
            result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                    .setErrorStatus(SamlConstants.STATUS_REQUEST_UNSUPPORTED);
            return false;
        }
        String signedInfo = request.getSignedInfo();
        String sigAlg = request.getSignatureAlgorithm();

        if (signature != null && signedInfo != null && sigAlg != null) {

            LOG.debug("* Request is signed");

            try {
                validator.validate(signedInfo, signature, sigAlg);
            } catch (NoSuchAlgorithmException | TechnicalException | InvalidSignatureException e) {
                LOG.error("Request signature is invalid");
                result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                        .setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
                return false;
            }

            LOG.debug("* Request signature is valid");

        } else {

            LOG.debug("* Request is not signed");

            if (!configurationService.getConfiguration().getSamlIdpConfiguration().isAllowUnsecureRequests()) {
                LOG.error("Unsigned requests are not supported.");
                result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                        .setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
                return false;
            }
        }

        return true;
    }

    private boolean validatePostRequest(Validator validator, AuthentRequest ar, RequestParsingInfo result) {

        LOG.debug("Validate query parameters of HTTP-POST Binding");

        if (ar.isSigned()) {

            LOG.debug("* Request is signed");

            try {
                validator.validate(ar);
            } catch (NoSuchAlgorithmException | UnsignedSAMLObjectException | TechnicalException
                    | UntrustedSignerException | InvalidSignatureException e) {
                LOG.error("Request signature is invalid");
                result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
                return false;
            }

            LOG.debug("* Request signature is valid");

        } else {
            LOG.debug("* Request is not signed");

            if (!configurationService.getConfiguration().getSamlIdpConfiguration().isAllowUnsecureRequests()) {
                LOG.error("Unsigned requests are not supported.");
                result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
                return false;
            }

        }

        return true;
    }

    public ResponseData generateSuccessResponse(AuthPolicyDecision decision, RequestParsingInfo requestParsingInfo,
                                                UserSession userSession) throws SamlException {

        LOG.debug("Generating a new SAML Response");

        String spEntityID = requestParsingInfo.getSourceApplicationName();
        String requestID = requestParsingInfo.getRequestId();
        String userId = userSession.getUserId();
        AuthSession authSession = decision.getValidatedAuthSession();
        String authnLevel = authSession.getAuthLevel().getUrn();
        DateTime authnInstant = authSession.getAuthInstant();
        String sessionId = userSession.getId();
        String destinationUrl = requestParsingInfo.getResponseUrl();

        // Determine the assertion consumer endpoint

        LOG.debug("* Entity ID: {}", spEntityID);
        LOG.debug("* User ID: {}", userId);
        LOG.debug("* In response to request: {}", requestID);
        LOG.debug("* AuthLevel: {}", authnLevel);
        LOG.debug("* Authentication time: {}", authnInstant.toString());

        // Build the assertion
        try {
            Assertion assertion = AssertionBuilder.getInstance()
                    .setIssuer(metadataService.getIdpMetadata().getEntityID())
                    .setSubject(userId, SamlConstants.NAMEID_UNSPECIFIED)
                    .setSubjectConfirmation(SamlConstants.SUBJECT_CONFIRMATION_BEARER, requestID, destinationUrl)
                    .setConditions(spEntityID,
                            configurationService.getConfiguration().getSamlIdpConfiguration().getTokenValidityLength(),
                            configurationService.getConfiguration().getSamlIdpConfiguration().getAllowedTimeOffset())
                    .setAuthentStatement(authnLevel, authnInstant, sessionId).build();

            LOG.debug("* SAML Assertion built");

            // Build the response
            AuthentResponse response = AuthentResponseBuilder.getInstance()
                    .setIssuer(metadataService.getIdpMetadata().getEntityID()).setStatus(true, null)
                    .setDestination(destinationUrl).setAssertion(assertion).build();

            LOG.debug("* SAML response built");

            // Sign the response
            signer.signEmbedded(response);

            LOG.debug("* SAML response signed");

            String data = DecodeUtils.encode(response.toString().getBytes(), false);

            return new ResponseData().setUrl(requestParsingInfo.getResponseUrl())
                    .setData(data)
                    .setRelayState(requestParsingInfo.getRelayState());

        } catch (TechnicalException | IOException ex) {
            String message = "Technical error when building SAML response";
            LOG.error("{}: {}", message, ex.getMessage());
            throw new SamlException(message, ex);
        }
    }

    public ResponseData generateErrorResponse(RequestParsingInfo requestParsingInfo) throws SamlException {

        LOG.debug("Generating a new SAML Error Response");

        String destinationUrl = requestParsingInfo.getResponseUrl();

        if (destinationUrl == null) {
            String message = "* Destination URL cannot be null";
            LOG.error(message);
            throw new SamlException(message);
        }

        // Build the response
        try {

            // Build the response
            AuthentResponse response = AuthentResponseBuilder.getInstance()
                    .setIssuer(metadataService.getIdpMetadata().getEntityID())
                    .setStatus(false, requestParsingInfo.getErrorStatus()).setDestination(destinationUrl).build();

            LOG.debug("* SAML response built");

            String data = DecodeUtils.encode(response.toString().getBytes(), false);

            return new ResponseData().setUrl(requestParsingInfo.getResponseUrl())
                    .setData(data)
                    .setRelayState(requestParsingInfo.getRelayState());

        } catch (TechnicalException | IOException ex) {
            String message = "Technical error when building SAML response";
            LOG.error("{}: {}", message, ex.getMessage());
            throw new SamlException(message, ex);
        }
    }

    private Endpoint findResponseEndpoint(AuthentRequest ar) {
        Endpoint selectedEndpoint = null;

        outerloop:
        for (SpSsoDescriptor descriptor : metadataService.getSpMetadata(ar.getIssuer())
                .getSpSsoDescriptors()) {
            for (Endpoint endpoint : descriptor.getAssertionConsumerServices()) {

                // Preference to the location specified in the request
                if (ar.getPreferredEndPoint() != null) {
                    if (ar.getPreferEndpointIndex()
                            && ar.getPreferredEndPoint().getIndex().equals(endpoint.getIndex())) {
                        selectedEndpoint = endpoint;
                        break outerloop;
                    }
                    if (!ar.getPreferEndpointIndex()
                            && ar.getPreferredEndPoint().getLocation().equals(endpoint.getLocation())
                            && ar.getPreferredEndPoint().getBinding().equals(endpoint.getBinding())) {
                        selectedEndpoint = endpoint;
                        break outerloop;
                    }
                } else {
                    if (endpoint.isDefault()) {
                        selectedEndpoint = endpoint;
                    }
                }
            }
        }

        return selectedEndpoint;
    }

    private Endpoint findRequestEndpoint(Metadata remoteIdpMetadata) {
        Endpoint selectedEndpoint = null;

        // Find IDP endoint
        for (Endpoint endpoint : remoteIdpMetadata.getIdpSsoDescriptors().get(0).getSsoEndpoints()) {
            if (selectedEndpoint == null) {
                selectedEndpoint = endpoint;
            } else {
                if (endpoint.isDefault()) {
                    selectedEndpoint = endpoint;
                }
            }
        }

        return selectedEndpoint;
    }

    public SamlAuthRequestGenerationResult generateAuthentRequest(Metadata remoteIdpMetadata,
                                                                  ArrayList<String> requestedAuthnContext, String comparison, String transactionId) throws SamlException {

        LOG.debug("Generating a new SAML Request");

        SamlAuthRequestGenerationResult result = new SamlAuthRequestGenerationResult();

        try {
            Metadata idpMetadata = metadataService.getIdpMetadata();

            Endpoint remoteEndpoint = findRequestEndpoint(remoteIdpMetadata);
            result.setTargetEndpoint(remoteEndpoint);

            AuthentRequest authentRequest = AuthentRequestBuilder.getInstance().setIssuer(idpMetadata.getEntityID())
                    .setDestination(remoteEndpoint.getLocation()).setForceAuthent(false).setIsPassive(false)
                    .setRequestedAuthnContext(requestedAuthnContext, comparison).build();

            result.setRequestId(authentRequest.getId());

            if (remoteEndpoint.getBinding().equals(SamlConstants.BINDING_HTTP_POST)) {
                signer.signEmbedded(authentRequest);
                result.setSerializedRequest(DecodeUtils.encode(authentRequest.toString().getBytes(), false))
                        .setRelayState(transactionId);
            } else {
                // Generate the information to sign
                String encodedSamlRequest = UriUtils
                        .encode(DecodeUtils.encode(authentRequest.toString().getBytes(), true), "UTF-8");
                String encodedRelayState = UriUtils.encode(transactionId, "UTF-8");
                String encodedSigAlg = UriUtils.encode(SamlConstants.SIGNATURE_ALG_RSA_SHA256, "UTF-8");

                String signedInfo = "SAMLRequest=" + encodedSamlRequest + "&RelayState=" + encodedRelayState
                        + "&SigAlg=" + encodedSigAlg;
                String encodedSignature = UriUtils.encode(DecodeUtils.encode(signer.signExternal(signedInfo), false),
                        "UTF-8");

                result.setSignature(encodedSignature).setSerializedRequest(encodedSamlRequest)
                        .setRelayState(encodedRelayState).setSignatureAlgorithm(encodedSigAlg);
            }

            LOG.debug("* SAML request built");
            result.setSuccess(true);

            return result;

        } catch (TechnicalException | IOException ex) {
            String message = "Technical error when building SAML request";
            LOG.error("{}: {}", message, ex.getMessage());
            throw new SamlException(message, ex);
        }

    }

}
