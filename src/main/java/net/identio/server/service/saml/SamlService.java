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
package net.identio.server.service.saml;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.zip.DataFormatException;

import org.apache.xml.security.exceptions.Base64DecodingException;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriUtils;

import net.identio.saml.Assertion;
import net.identio.saml.AssertionBuilder;
import net.identio.saml.AuthentRequest;
import net.identio.saml.AuthentRequestBuilder;
import net.identio.saml.AuthentResponse;
import net.identio.saml.AuthentResponseBuilder;
import net.identio.saml.Endpoint;
import net.identio.saml.IdpSsoDescriptor;
import net.identio.saml.Metadata;
import net.identio.saml.SamlConstants;
import net.identio.saml.Signer;
import net.identio.saml.SpSsoDescriptor;
import net.identio.saml.Validator;
import net.identio.saml.exceptions.InvalidRequestException;
import net.identio.saml.exceptions.InvalidSignatureException;
import net.identio.saml.exceptions.TechnicalException;
import net.identio.saml.exceptions.UnsignedSAMLObjectException;
import net.identio.saml.exceptions.UntrustedSignerException;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.exceptions.SamlException;
import net.identio.server.exceptions.UnknownAuthLevelException;
import net.identio.server.model.AuthLevel;
import net.identio.server.model.AuthPolicyDecision;
import net.identio.server.model.AuthRequestValidationResult;
import net.identio.server.model.AuthSession;
import net.identio.server.model.ErrorStatus;
import net.identio.server.model.IdentioConfiguration;
import net.identio.server.model.InboundRequest;
import net.identio.server.model.RequestType;
import net.identio.server.model.SamlAuthRequestGenerationResult;
import net.identio.server.model.UserSession;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.utils.DecodeUtils;

@Service
@Scope("singleton")
public class SamlService {

	private static final Logger LOG = LoggerFactory.getLogger(SamlService.class);

	private Signer signer;

	private MetadataService metadataService;

	private ConfigurationService configurationService;

	private AuthPolicyService authPolicyService;

	private HashMap<ErrorStatus, String> errorMapping;

	@Autowired
	public SamlService(ConfigurationService configurationService, MetadataService metadataService,
			AuthPolicyService authPolicyService) throws InitializationException {

		this.configurationService = configurationService;
		this.metadataService = metadataService;
		this.authPolicyService = authPolicyService;

		initErrorMapping();

		try {

			initSigner(configurationService.getConfiguration());
		} catch (TechnicalException ex) {
			String message = "Could not initialize SamlService";
			LOG.error("{}: {}", message, ex.getMessage());
			throw new InitializationException(message, ex);
		}
	}

	private void initSigner(IdentioConfiguration config) throws TechnicalException {

		String keystoreFile = config.getSamlIdpConfiguration().getKeystore();
		String keystorePassword = config.getSamlIdpConfiguration().getKeystorePassword();
		boolean isCertificateCheckEnabled = config.getSamlIdpConfiguration().isCertificateCheckEnabled();

		LOG.debug("Initializing SAML signer...");

		signer = new Signer(keystoreFile, keystorePassword, isCertificateCheckEnabled,
				SamlConstants.SIGNATURE_ALG_RSA_SHA256);
	}

	private void initErrorMapping() {

		errorMapping = new HashMap<>();

		errorMapping.put(ErrorStatus.BUILD_AUTHENT_REQUEST_FAILED, SamlConstants.STATUS_REQUEST_UNSUPPORTED);
		errorMapping.put(ErrorStatus.AUTH_LEVEL_UNKNOWN, SamlConstants.STATUS_NO_AUTHN_CONTEXT);
		errorMapping.put(ErrorStatus.AUTHENT_REQUEST_ISSUER_EMPTY, SamlConstants.STATUS_REQUEST_DENIED);
		errorMapping.put(ErrorStatus.AUTHENT_REQUEST_ISSUER_UNKNOWN, SamlConstants.STATUS_REQUEST_DENIED);
		errorMapping.put(ErrorStatus.AUTHENT_REQUEST_NO_DESTINATION, SamlConstants.STATUS_UNSUPPORTED_BINDING);
		errorMapping.put(ErrorStatus.AUTHENT_REQUEST_UNKNOWN_ENDPOINT, SamlConstants.STATUS_UNSUPPORTED_BINDING);
		errorMapping.put(ErrorStatus.AUTHENT_REQUEST_INVALID_ENCODING, SamlConstants.STATUS_REQUEST_UNSUPPORTED);
		errorMapping.put(ErrorStatus.AUTHENT_REQUEST_SIGNATURE_INVALID, SamlConstants.STATUS_REQUEST_DENIED);
		errorMapping.put(ErrorStatus.AUTHENT_REQUEST_NOT_SIGNED, SamlConstants.STATUS_REQUEST_DENIED);
	}

	public AuthRequestValidationResult validateAuthentRequest(InboundRequest request) {

		LOG.debug("Starting SAML Authentication Request validation...");

		AuthRequestValidationResult result = new AuthRequestValidationResult();

		// Parse the authentication request
		AuthentRequest ar = null;

		try {
			ar = AuthentRequestBuilder.getInstance().build(request.getSerializedRequest(), false);
		} catch (TechnicalException | InvalidRequestException e1) {
			LOG.error("Impossible to build AuthentRequest");
			return result.setSuccess(false).setErrorStatus(ErrorStatus.BUILD_AUTHENT_REQUEST_FAILED);
		}

		// Extract interesting values
		String requestIssuer = ar.getIssuer();

		ArrayList<String> requestedAuthnContext = ar.getRequestedAuthnContext();
		String comparison = ar.getAuthnContextComparison();
		boolean forceAuthn = ar.isForceAuthn();
		String requestId = ar.getId();
		Endpoint destinationEndpoint = findResponseEndpoint(ar);

		result.setRequestId(requestId).setSourceApplicationName(requestIssuer).setAuthLevelComparison(comparison)
				.setForceAuthentication(forceAuthn).setRequestType(RequestType.SAML)
				.setRelayState(request.getRelayState()).setResponseUrl(destinationEndpoint.getLocation());

		// Extract the requested authentication level, if any
		if (requestedAuthnContext != null) {
			ArrayList<AuthLevel> requestedAuthLevels = new ArrayList<>();

			for (String authLevelString : requestedAuthnContext) {
				try {
					requestedAuthLevels.add(authPolicyService.getAuthLevelByUrn(authLevelString));
				} catch (UnknownAuthLevelException e) {
					return result.setSuccess(false).setErrorStatus(ErrorStatus.AUTH_LEVEL_UNKNOWN);
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
			return result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_ISSUER_EMPTY);
		}

		// Check if the issuer is registered
		Validator validator = metadataService.getSpValidator(requestIssuer);
		if (validator == null) {
			LOG.error("No validator found for issuer {}", requestIssuer);
			return result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_ISSUER_UNKNOWN);
		}

		// Check that we are the recipient of the Authentication Request
		String destination = ar.getDestination();

		if (destination == null) {
			LOG.error("No destination specified in request");
			return result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_NO_DESTINATION);

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
				return result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_UNKNOWN_ENDPOINT);
			}
		}

		// Check the signature and the conditions
		if ((SamlConstants.BINDING_HTTP_REDIRECT.equals(request.getBinding())
				&& !validateRedirectRequest(validator, request, result))
				|| !validatePostRequest(validator, ar, result)) {
			return result;
		}

		LOG.debug("* Request is valid");
		result.setSuccess(true);

		return result;

	}

	private boolean validateRedirectRequest(Validator validator, InboundRequest request,
			AuthRequestValidationResult result) {

		LOG.debug("Validate query parameters of HTTP-Redirect Binding");

		byte[] signature;
		try {
			signature = DecodeUtils.decode(request.getSignatureValue(), false);
		} catch (Base64DecodingException | IOException | DataFormatException e) {
			result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_INVALID_ENCODING);
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
				result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_SIGNATURE_INVALID);
				return false;
			}

			LOG.debug("* Request signature is valid");

		} else {

			LOG.debug("* Request is not signed");

			if (!configurationService.getConfiguration().getSamlIdpConfiguration().isAllowUnsecureRequests()) {
				LOG.error("Unsigned requests are not supported.");
				result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_NOT_SIGNED);
				return false;
			}
		}

		return true;
	}

	private boolean validatePostRequest(Validator validator, AuthentRequest ar, AuthRequestValidationResult result) {

		LOG.debug("Validate query parameters of HTTP-POST Binding");

		if (ar.isSigned()) {

			LOG.debug("* Request is signed");

			try {
				validator.validate(ar);
			} catch (NoSuchAlgorithmException | UnsignedSAMLObjectException | TechnicalException
					| UntrustedSignerException | InvalidSignatureException e) {
				LOG.error("Request signature is invalid");
				result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_SIGNATURE_INVALID);
				return false;
			}

			LOG.debug("* Request signature is valid");

		} else {
			LOG.debug("* Request is not signed");

			if (!configurationService.getConfiguration().getSamlIdpConfiguration().isAllowUnsecureRequests()) {
				LOG.error("Unsigned requests are not supported.");
				result.setSuccess(false).setErrorStatus(ErrorStatus.AUTHENT_REQUEST_NOT_SIGNED);
				return false;
			}

		}

		return true;
	}

	public String generateSuccessResponse(AuthPolicyDecision decision, AuthRequestValidationResult result,
			UserSession userSession) throws SamlException {

		LOG.debug("Generating a new SAML Response");

		String spEntityID = result.getSourceApplicationName();
		String requestID = result.getRequestId();
		String userId = userSession.getUserId();
		AuthSession authSession = decision.getValidatedAuthSession();
		String authnLevel = authSession.getAuthLevel().getUrn();
		DateTime authnInstant = authSession.getAuthInstant();
		String sessionId = userSession.getId();
		String destinationUrl = result.getResponseUrl();

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

			return DecodeUtils.encode(response.toString().getBytes(), false);

		} catch (TechnicalException | IOException ex) {
			String message = "Technical error when building SAML response";
			LOG.error("{}: {}", message, ex.getMessage());
			throw new SamlException(message, ex);
		}
	}

	public String generateErrorResponse(AuthRequestValidationResult result) throws SamlException {

		LOG.debug("Generating a new SAML Error Response");

		String destinationUrl = result.getResponseUrl();

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
					.setStatus(false, errorMapping.get(result.getErrorStatus())).setDestination(destinationUrl).build();

			LOG.debug("* SAML response built");

			return DecodeUtils.encode(response.toString().getBytes(), false);

		} catch (TechnicalException | IOException ex) {
			String message = "Technical error when building SAML response";
			LOG.error("{}: {}", message, ex.getMessage());
			throw new SamlException(message, ex);
		}
	}

	private Endpoint findResponseEndpoint(AuthentRequest ar) {
		Endpoint selectedEndpoint = null;

		outerloop: for (SpSsoDescriptor descriptor : metadataService.getSpMetadata(ar.getIssuer())
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
					if (endpoint == null) {
						selectedEndpoint = endpoint;
					}
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
