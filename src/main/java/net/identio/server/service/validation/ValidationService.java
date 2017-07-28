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
package net.identio.server.service.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import net.identio.server.exceptions.AuthMethodNotAllowedException;
import net.identio.server.exceptions.SamlException;
import net.identio.server.exceptions.UnknownAuthMethodException;
import net.identio.server.exceptions.ValidationException;
import net.identio.server.model.AuthLevel;
import net.identio.server.model.AuthMethod;
import net.identio.server.model.AuthPolicyDecision;
import net.identio.server.model.AuthRequestValidationResult;
import net.identio.server.model.Authentication;
import net.identio.server.model.AuthenticationResult;
import net.identio.server.model.AuthenticationResultStatus;
import net.identio.server.model.ErrorStatus;
import net.identio.server.model.InboundRequest;
import net.identio.server.model.OAuthInboundRequest;
import net.identio.server.model.ProtocolType;
import net.identio.server.model.SamlAuthMethod;
import net.identio.server.model.SamlAuthRequestGenerationResult;
import net.identio.server.model.SamlInboundRequest;
import net.identio.server.model.State;
import net.identio.server.model.TransactionData;
import net.identio.server.model.UserSession;
import net.identio.server.model.ValidationResult;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.saml.SamlAuthenticationProvider;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.oauth.OAuthService;
import net.identio.server.service.saml.SamlService;
import net.identio.server.service.transaction.TransactionService;
import net.identio.server.service.usersession.UserSessionService;

@Service
@Scope("singleton")
public class ValidationService {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationService.class);

	@Autowired
	private SamlService samlService;

	@Autowired
	private UserSessionService userSessionService;

	@Autowired
	private OAuthService oauthService;

	@Autowired
	private AuthPolicyService authPolicyService;

	@Autowired
	private TransactionService transactionService;

	@Autowired
	private AuthenticationService authenticationService;

	@Autowired
	private SamlAuthenticationProvider samlAuthenticationProvider;

	public ValidationResult validateAuthentRequest(InboundRequest request, String sessionId)
			throws ValidationException {

		ValidationResult validationResult = new ValidationResult();

		// Validate the request
		AuthRequestValidationResult arValidationResult = null;

		if (request instanceof SamlInboundRequest) {
			arValidationResult = samlService.validateAuthentRequest((SamlInboundRequest) request);
		}
		if (request instanceof OAuthInboundRequest) {
            arValidationResult = oauthService.validateAuthentRequest((OAuthInboundRequest) request);
		}

		validationResult.setArValidationResult(arValidationResult);

		if (!arValidationResult.isSuccess()) {

			if (arValidationResult.getResponseUrl() != null) {
                validationResult.setState(State.RESPONSE);
                validationResult.setResponseData(generateFatalErrorResponse(arValidationResult));
            }
            else {
			    validationResult.setState(State.ERROR);
            }

			return validationResult;
		}

		TransactionData transactionData = transactionService.createTransaction();
		UserSession userSession = userSessionService.getUserSession(sessionId);
		transactionData.setUserSession(userSession);

		validationResult.setTransactionId(transactionData.getTransactionId());
		validationResult.setSessionId(userSession.getId());

		// Determine target auth levels and auth methods
		ArrayList<AuthLevel> targetAuthLevels = authPolicyService.determineTargetAuthLevel(arValidationResult);
		HashSet<AuthMethod> targetAuthMethods = authPolicyService.determineTargetAuthMethods(targetAuthLevels);

		// Check if previous authentications match
		AuthPolicyDecision decision = authPolicyService.checkPreviousAuthSessions(userSession, targetAuthLevels);

		validationResult.setState(decision.getNextState());

		if (decision.getNextState() == State.RESPONSE) {
			validationResult.setResponseData(generateSuccessResponse(decision, arValidationResult, transactionData));
		} else {
			// Save data that will need later in the transaction
			transactionData.setState(decision.getNextState());
			transactionData.setArValidationResult(arValidationResult);
			transactionData.setTargetAuthLevels(targetAuthLevels);
			transactionData.setTargetAuthMethods(targetAuthMethods);
		}

		return validationResult;
	}

	public ValidationResult validateTransparentAuthentication(ValidationResult validationResult,
			Authentication authentication) throws ValidationException {

		LOG.debug("Check for transparent authentication");

		// Fetch transaction
		// As we just created the transaction, there is no need to check the
		// coherence with the session
		TransactionData transactionData = transactionService.getTransaction(validationResult.getTransactionId());
		UserSession userSession = transactionData.getUserSession();

		if (authentication != null) {

			AuthenticationResult result = authenticationService.validateTransparent(authentication, transactionData);

			if (result != null && result.getStatus() == AuthenticationResultStatus.SUCCESS) {

				AuthPolicyDecision decision = authPolicyService.checkAuthPolicyCompliance(userSession, result,
						transactionData.getTargetAuthLevels(), transactionData.getSelectedAuthMethod(),
						transactionData.getState());

				validationResult.setState(decision.getNextState());

				if (decision.getNextState() == State.RESPONSE) {

					validationResult.setResponseData(generateSuccessResponse(decision,
							validationResult.getArValidationResult(), transactionData));
				}

				return validationResult;
			}

		}

		return validationResult;
	}

	public ValidationResult validateExplicitAuthentication(String transactionId, String sessionId,
			String authMethodName, Authentication authentication) throws ValidationException {

		LOG.debug("Validating explicit authentication: {}", authMethodName);

		TransactionData transactionData = getTransaction(sessionId, transactionId);

		ValidationResult validationResult = new ValidationResult();
		validationResult.setArValidationResult(transactionData.getArValidationResult());
		validationResult.setSessionId(sessionId);
		validationResult.setTransactionId(transactionId);

		// Try to map the authmethodname to a known method
		AuthMethod authMethod = null;

		if (authMethodName != null) {
			try {
				authMethod = authPolicyService.getAuthMethodByName(authMethodName);
			} catch (UnknownAuthMethodException e) {
				return generateTemporaryErrorResponse(validationResult, transactionData,
						ErrorStatus.AUTH_METHOD_UNKNOWN);
			}
		} else {
			// The authentication method name is not provided, we use the method
			// stored in the transaction
			AuthMethod transactionAuthMethod = transactionData.getSelectedAuthMethod();

			if (transactionAuthMethod != null) {
				authMethod = transactionAuthMethod;
			} else {
				return generateTemporaryErrorResponse(validationResult, transactionData,
						ErrorStatus.AUTH_METHOD_UNKNOWN);
			}
		}

		if (authentication == null) {
			return generateTemporaryErrorResponse(validationResult, transactionData, ErrorStatus.AUTH_NO_CREDENTIALS);
		} else {

			if (transactionData.getState() == State.AUTH) {
				transactionData.setSelectedAuthMethod(authMethod);
			}

			// Check that the authentication method is listed in the allowed
			// methods for this transaction
			try {
				authPolicyService.checkAllowedAuthMethods(transactionData.getState(),
						transactionData.getTargetAuthMethods(), transactionData.getSelectedAuthMethod(), authMethod);
			} catch (UnknownAuthMethodException e) {
				return generateTemporaryErrorResponse(validationResult, transactionData,
						ErrorStatus.AUTH_METHOD_UNKNOWN);
			} catch (AuthMethodNotAllowedException e) {
				return generateTemporaryErrorResponse(validationResult, transactionData,
						ErrorStatus.AUTH_METHOD_NOT_ALLOWED);
			}

			AuthenticationResult authResult = authenticationService.validateExplicit(authMethod, authentication,
					transactionData);

			if (authResult != null) {

				switch (authResult.getStatus()) {

				case SUCCESS:

					AuthPolicyDecision decision = authPolicyService.checkAuthPolicyCompliance(
							transactionData.getUserSession(), authResult, transactionData.getTargetAuthLevels(),
							transactionData.getSelectedAuthMethod(), transactionData.getState());

					validationResult.setState(decision.getNextState());
					transactionData.setState(decision.getNextState());

					if (decision.getNextState() == State.RESPONSE) {
						validationResult.setResponseData(generateSuccessResponse(decision,
								transactionData.getArValidationResult(), transactionData));
					}
					break;

				case FAIL:
					validationResult.setState(transactionData.getState());
					validationResult.setErrorStatus(authResult.getErrorStatus());
					break;

				case CHALLENGE:
					validationResult.setState(transactionData.getState());
					validationResult.setChallengeType(authResult.getChallengeType());
					validationResult.setChallengeValue(authResult.getChallengeValue());
					break;

				default:
					String message = "Unknown transaction state";
					LOG.error(message);
					throw new ValidationException(message);
				}
			}

			return validationResult;
		}

	}

	public List<AuthMethod> getAuthMethods(String transactionId, String sessionId) throws ValidationException {

		TransactionData transactionData = getTransaction(sessionId, transactionId);

		switch (transactionData.getState()) {
		case AUTH:
			return transactionData.getTargetAuthMethods().stream().filter(x -> x.isExplicit())
					.sorted((x1, x2) -> x1.getName().compareTo(x2.getName())).collect(Collectors.toList());

		case STEP_UP_AUTHENTICATION:
			return Arrays.asList(transactionData.getSelectedAuthMethod().getStepUpAuthentication().getAuthMethod());
		default:
			return null;
		}
	}

	public SamlAuthRequestGenerationResult initSamlRequest(String transactionId, String sessionId,
			String authMethodName) throws ValidationException {

		TransactionData transactionData = getTransaction(sessionId, transactionId);

		AuthMethod authMethod = null;
		try {
			authMethod = authPolicyService.getAuthMethodByName(authMethodName);
		} catch (UnknownAuthMethodException e) {
			return new SamlAuthRequestGenerationResult().setSuccess(false)
					.setErrorStatus(ErrorStatus.AUTH_METHOD_UNKNOWN);
		}

		transactionData.setSelectedAuthMethod(authMethod);

		try {
			authPolicyService.checkAllowedAuthMethods(transactionData.getState(),
					transactionData.getTargetAuthMethods(), transactionData.getSelectedAuthMethod(), authMethod);
		} catch (UnknownAuthMethodException e) {
			return new SamlAuthRequestGenerationResult().setSuccess(false)
					.setErrorStatus(ErrorStatus.AUTH_METHOD_UNKNOWN);
		} catch (AuthMethodNotAllowedException e) {
			return new SamlAuthRequestGenerationResult().setSuccess(false)
					.setErrorStatus(ErrorStatus.AUTH_METHOD_NOT_ALLOWED);
		}

		try {
			SamlAuthRequestGenerationResult result = samlAuthenticationProvider.initRequest((SamlAuthMethod) authMethod,
					transactionData.getTargetAuthLevels(), transactionId);

			transactionData.setSamlProxyRequestId(result.getRequestId());
			return result;

		} catch (SamlException e) {
			String message = "An error occured when generating authent request";
			LOG.error(message);
			throw new ValidationException(message, e);
		}
	}

	private String generateSuccessResponse(AuthPolicyDecision decision, AuthRequestValidationResult arValidationResult,
			TransactionData transactionData) throws ValidationException {

		if (arValidationResult.getProtocolType() == ProtocolType.SAML) {

			try {
				return samlService.generateSuccessResponse(decision, arValidationResult,
						transactionData.getUserSession());
			} catch (SamlException e) {
				String message = "An error occured when generating response";
				LOG.error(message);
				throw new ValidationException(message, e);
			} finally {
				transactionService.removeTransactionData(transactionData);
			}
		} else {
			return oauthService.generateSuccessResponse(arValidationResult, transactionData.getUserSession());
		}
	}

	private String generateFatalErrorResponse(AuthRequestValidationResult arValidationResult)
			throws ValidationException {

		if (arValidationResult.getProtocolType() == ProtocolType.SAML) {

			try {
				return samlService.generateErrorResponse(arValidationResult);
			} catch (SamlException e) {
				String message = "An error occured when generating response";
				LOG.error(message);
				throw new ValidationException(message, e);
			}
		} else {
			return oauthService.generateErrorResponse(arValidationResult);
		}
	}

	private ValidationResult generateTemporaryErrorResponse(ValidationResult validationResult,
			TransactionData transactionData, ErrorStatus status) {

		// The state remains untouched
		validationResult.setState(transactionData.getState());
		validationResult.setErrorStatus(status);
		return validationResult;
	}

	private TransactionData getTransaction(String sessionId, String transactionId) throws ValidationException {

		LOG.debug("Security verification of coherence between transaction ID and session ID");

		TransactionData transactionData = transactionService.getTransaction(transactionId);

		if (transactionData.getTransactionId() == null) {
			String message = "Could not find a valid transaction";
			LOG.error(message);
			throw new ValidationException(message);
		}

		if (!sessionId.equals(transactionData.getUserSession().getId())) {
			transactionService.removeTransactionData(transactionData);

			String message = "Session ID in transaction doesn't match browser session ID. Possible session fixation attack ?";
			LOG.error(message);
			throw new ValidationException(message);
		}

		LOG.debug("Security verification OK");

		return transactionData;
	}

}
