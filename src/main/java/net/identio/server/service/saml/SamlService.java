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
import net.identio.server.boot.GlobalConfiguration;
import net.identio.server.boot.IdentioServerApplication;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.model.*;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.authpolicy.model.AuthPolicyDecision;
import net.identio.server.service.orchestration.model.RequestParsingInfo;
import net.identio.server.service.orchestration.model.RequestParsingStatus;
import net.identio.server.service.orchestration.model.ResponseData;
import net.identio.server.service.orchestration.model.SamlAuthRequest;
import net.identio.server.utils.DecodeUtils;
import net.identio.server.utils.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriUtils;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;

@Service
public class SamlService {

    private static final Logger LOG = LoggerFactory.getLogger(SamlService.class);

    private Signer signer;

    private MetadataService metadataService;

    private AuthPolicyService authPolicyService;

    private SamlConfiguration samlConfiguration;

    private GlobalConfiguration globalConfig;

    @Autowired
    public SamlService(GlobalConfiguration globalConfig, SamlConfiguration samlConfiguration, MetadataService metadataService,
                       AuthPolicyService authPolicyService) {

        this.samlConfiguration = samlConfiguration;
        this.globalConfig = globalConfig;

        this.metadataService = metadataService;
        this.authPolicyService = authPolicyService;

        try {

            initSigner();
        } catch (TechnicalException ex) {
            IdentioServerApplication.quitOnStartupError(LOG,
                    "Could not initialize SAML service: " + ex.getMessage());
        }
    }

    private void initSigner() throws TechnicalException {

        String keystoreFile = globalConfig.getSignatureKeystorePath();
        String keystorePassword = globalConfig.getSignatureKeystorePassword();
        boolean isCertificateCheckEnabled = samlConfiguration.isCertificateCheckEnabled();

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

        result.setRequestId(requestId).setSourceApplication(requestIssuer).setAuthLevelComparison(comparison)
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

        String signature = request.getSignatureValue();
        String signedInfo = request.getSignedInfo();
        String sigAlg = request.getSignatureAlgorithm();

        if (signature != null && signedInfo != null && sigAlg != null) {

            LOG.debug("* Request is signed");

            Result<byte[]> decodedSignature = DecodeUtils.decode(request.getSignatureValue(), false);

            if (!decodedSignature.isSuccess()) {
                result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                        .setErrorStatus(SamlConstants.STATUS_REQUEST_UNSUPPORTED);
                return false;
            }

            try {
                if (!validator.validate(signedInfo, decodedSignature.get(), sigAlg)) {
                    return false;
                }
            } catch (NoSuchAlgorithmException | TechnicalException | InvalidSignatureException e) {
                LOG.error("Request signature is invalid");
                result.setStatus(RequestParsingStatus.RESPONSE_ERROR)
                        .setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
                return false;
            }

            LOG.debug("* Request signature is valid");

        } else {

            LOG.debug("* Request is not signed");

            if (!samlConfiguration.isAllowUnsecureRequests()) {
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

            if (!samlConfiguration.isAllowUnsecureRequests()) {
                LOG.error("Unsigned requests are not supported.");
                result.setStatus(RequestParsingStatus.RESPONSE_ERROR).setErrorStatus(SamlConstants.STATUS_REQUEST_DENIED);
                return false;
            }

        }

        return true;
    }

    public Result<ResponseData> generateSuccessResponse(AuthPolicyDecision decision, RequestParsingInfo requestParsingInfo,
                                                        UserSession userSession) {

        LOG.debug("Generating a new SAML Response");

        String spEntityID = requestParsingInfo.getSourceApplication();
        String requestID = requestParsingInfo.getRequestId();
        String userId = userSession.getUserId();
        AuthSession authSession = decision.getValidatedAuthSession();
        String authnLevel = authSession.getAuthLevel().getUrn();
        Instant authnInstant = authSession.getAuthInstant();
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
                            samlConfiguration.getTokenValidityLength(),
                            samlConfiguration.getAllowedTimeOffset())
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

            Result<String> data = DecodeUtils.encode(response.toString().getBytes(), false);

            if (!data.isSuccess()) return Result.serverError();

            return Result.success(new ResponseData().setProtocolType(ProtocolType.SAML).setUrl(requestParsingInfo.getResponseUrl())
                    .setData(data.get())
                    .setRelayState(requestParsingInfo.getRelayState()));

        } catch (TechnicalException e) {
            LOG.error("Technical error when building SAML response: {}", e.getMessage());
            return Result.serverError();
        }
    }

    public Result<ResponseData> generateErrorResponse(RequestParsingInfo requestParsingInfo) {

        LOG.debug("Generating a new SAML Error Response");

        String destinationUrl = requestParsingInfo.getResponseUrl();

        // Build the response
        try {

            // Build the response
            AuthentResponse response = AuthentResponseBuilder.getInstance()
                    .setIssuer(metadataService.getIdpMetadata().getEntityID())
                    .setStatus(false, requestParsingInfo.getErrorStatus()).setDestination(destinationUrl).build();

            LOG.debug("* SAML response built");

            Result<String> data = DecodeUtils.encode(response.toString().getBytes(), false);

            if (!data.isSuccess()) return Result.serverError();

            return Result.success(new ResponseData().setProtocolType(ProtocolType.SAML).setUrl(requestParsingInfo.getResponseUrl())
                    .setData(data.get())
                    .setRelayState(requestParsingInfo.getRelayState()));

        } catch (TechnicalException ex) {
            LOG.error("Technical error when building SAML response: {}", ex.getMessage());
            return Result.serverError();
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

    public Result<SamlAuthRequest> generateAuthentRequest(Metadata remoteIdpMetadata, ArrayList<String> requestedAuthnContext,
                                                          String comparison, String transactionId, String authMethodName) {

        LOG.debug("Generating a new SAML Request");

        SamlAuthRequest samlAuthRequest = new SamlAuthRequest();

        Metadata idpMetadata = metadataService.getIdpMetadata();

        Endpoint remoteEndpoint = findRequestEndpoint(remoteIdpMetadata);
        samlAuthRequest.setTargetEndpoint(remoteEndpoint);

        try {

            AuthentRequest authentRequest = AuthentRequestBuilder.getInstance().setIssuer(idpMetadata.getEntityID())
                    .setDestination(remoteEndpoint.getLocation()).setForceAuthent(false).setIsPassive(false)
                    .setRequestedAuthnContext(requestedAuthnContext, comparison).build();

            String relayState = generateRelayState(transactionId, authMethodName, authentRequest.getId());

            if (remoteEndpoint.getBinding().equals(SamlConstants.BINDING_HTTP_POST)) {

                signer.signEmbedded(authentRequest);

                Result<String> serializedRequest = DecodeUtils.encode(authentRequest.toString().getBytes(), false);

                if (!serializedRequest.isSuccess()) return Result.serverError();

                samlAuthRequest.setSerializedRequest(serializedRequest.get()).setRelayState(relayState);

            } else {

                // Generate the information to sign
                Result<String> serializedRequest = DecodeUtils.encode(authentRequest.toString().getBytes(), true);

                if (!serializedRequest.isSuccess()) return Result.serverError();

                String encodedSamlRequest = UriUtils.encode(serializedRequest.get(), StandardCharsets.UTF_8.name());
                String encodedRelayState = UriUtils.encode(relayState, StandardCharsets.UTF_8.name());
                String encodedSigAlg = UriUtils.encode(SamlConstants.SIGNATURE_ALG_RSA_SHA256, StandardCharsets.UTF_8.name());

                String signedInfo = "SAMLRequest=" + encodedSamlRequest + "&RelayState=" + encodedRelayState
                        + "&SigAlg=" + encodedSigAlg;

                Result<String> base64Signature = DecodeUtils.encode(signer.signExternal(signedInfo), false);

                if (!base64Signature.isSuccess()) return Result.serverError();

                String encodedSignature = UriUtils.encode(base64Signature.get(), StandardCharsets.UTF_8.name());

                samlAuthRequest.setSignature(encodedSignature).setSerializedRequest(encodedSamlRequest)
                        .setRelayState(encodedRelayState).setSignatureAlgorithm(encodedSigAlg);
            }

            return Result.success(samlAuthRequest);

        } catch (TechnicalException | UnsupportedEncodingException ex) {
            LOG.error("Technical error when building SAML request: {}", ex.getMessage());
            return Result.fail();
        }
    }

    private String generateRelayState(String transactionId, String authMethodName, String requestId) {

        return SecurityUtils.encrypt(transactionId + ":" + authMethodName + ":" + requestId);
    }
}
