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

package net.identio.server.service.orchestration;

import net.identio.server.exceptions.*;
import net.identio.server.model.*;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.model.Authentication;
import net.identio.server.service.authentication.model.AuthenticationResult;
import net.identio.server.service.authentication.model.AuthenticationResultStatus;
import net.identio.server.service.authentication.saml.SamlAuthenticationProvider;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.authpolicy.model.AuthPolicyDecision;
import net.identio.server.service.authpolicy.model.AuthPolicyDecisionStatus;
import net.identio.server.service.oauth.OAuthService;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.service.saml.SamlService;
import net.identio.server.service.transaction.model.TransactionData;
import net.identio.server.service.transaction.TransactionService;
import net.identio.server.service.transaction.model.TransactionState;
import net.identio.server.service.usersession.UserSessionService;
import net.identio.server.service.orchestration.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class AuthOrchestrationService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthOrchestrationService.class);

    @Autowired
    private UserSessionService userSessionService;

    @Autowired
    private SamlService samlService;

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

    public AuthenticationValidationResult handleTransparentAuthentication(Authentication authentication, String sessionId,
                                                                          String transactionId)
            throws WebSecurityException, ServerException {

        LOG.debug("Check for transparent authentication");

        TransactionData transactionData = transactionService.getTransaction(sessionId, transactionId);
        UserSession userSession = transactionData.getUserSession();

        AuthenticationResult result = authenticationService.validateTransparent(authentication, transactionData);

        if (result != null && result.getStatus() == AuthenticationResultStatus.SUCCESS) {

            AuthPolicyDecision decision = authPolicyService.checkAuthPolicyCompliance(userSession, result,
                    transactionData.getTargetAuthLevels());

            if (decision.getStatus() == AuthPolicyDecisionStatus.OK) {

                try {

                    return new AuthenticationValidationResult().setValidationStatus(ValidationStatus.RESPONSE)
                            .setResponseData(generateSuccessResponse(decision,
                                    transactionData.getRequestParsingInfo(), userSession));

                } catch (SamlException e) {
                    throw new ServerException(OrchestrationErrorStatus.SERVER_ERROR);
                } finally {
                    transactionService.removeTransactionData(transactionData);
                }
            }
        }

        return new AuthenticationValidationResult().setValidationStatus(ValidationStatus.AUTH);
    }

    public AuthenticationValidationResult handleExplicitAuthentication(String transactionId, String sessionId,
                                                                       String authMethodName, Authentication authentication)
            throws WebSecurityException, ValidationException, ServerException {

        LOG.debug("Validating explicit authentication: {}", authMethodName);

        TransactionData transactionData = transactionService.getTransaction(sessionId, transactionId);

        // Check that we are in the correct transaction state
        if (transactionData.getState() != TransactionState.AUTH) {
            transactionService.removeTransactionData(transactionData);
            throw new WebSecurityException(OrchestrationErrorStatus.INVALID_TRANSACTION);
        }

        AuthenticationValidationResult validationResult = new AuthenticationValidationResult();
        validationResult.setProtocolType(transactionData.getProtocolType());

        // Try to map the auth method name to a known method
        AuthMethod authMethod = null;

        try {

            authMethod = authMethodName != null ?
                    authPolicyService.getAuthMethodByName(authMethodName) : transactionData.getSelectedAuthMethod();

            authPolicyService.checkAllowedAuthMethods(transactionData.getTargetAuthMethods(), authMethod);

        } catch (UnknownAuthMethodException e) {
            transactionService.removeTransactionData(transactionData);
            throw new ValidationException(OrchestrationErrorStatus.AUTH_METHOD_UNKNOWN);
        } catch (AuthMethodNotAllowedException e) {
            transactionService.removeTransactionData(transactionData);
            throw new ValidationException(OrchestrationErrorStatus.AUTH_METHOD_NOT_ALLOWED);
        }

        AuthenticationResult authResult = authenticationService.validateExplicit(authMethod, authentication,
                transactionData);

        switch (authResult.getStatus()) {

            case SUCCESS:

                AuthPolicyDecision decision = authPolicyService.checkAuthPolicyCompliance(
                        transactionData.getUserSession(), authResult, transactionData.getTargetAuthLevels());

                if (decision.getStatus() == AuthPolicyDecisionStatus.OK) {

                    try {
                        validationResult.setValidationStatus(ValidationStatus.RESPONSE)
                                .setResponseData(generateSuccessResponse(
                                        decision,
                                        transactionData.getRequestParsingInfo(),
                                        transactionData.getUserSession()));

                    } catch (SamlException e) {
                        throw new ServerException(OrchestrationErrorStatus.SERVER_ERROR);
                    } finally {
                        transactionService.removeTransactionData(transactionData);
                    }
                }
                break;

            case FAIL:
                validationResult.setValidationStatus(ValidationStatus.ERROR)
                        .setErrorStatus(authResult.getErrorStatus());
                validationResult.setErrorStatus(authResult.getErrorStatus());
                break;

            case CHALLENGE:
                validationResult.setValidationStatus(ValidationStatus.CHALLENGE);
                validationResult.setChallengeType(authResult.getChallengeType());
                validationResult.setChallengeValue(authResult.getChallengeValue());
                break;
        }

        return validationResult;
    }

    public List<AuthMethod> getAuthMethods(String transactionId, String sessionId) throws WebSecurityException {

        TransactionData transactionData = transactionService.getTransaction(sessionId, transactionId);

        // Check that we are in the correct transaction state
        if (transactionData.getState() != TransactionState.AUTH) {
            transactionService.removeTransactionData(transactionData);
            throw new WebSecurityException(OrchestrationErrorStatus.INVALID_TRANSACTION);
        }

        return transactionData.getTargetAuthMethods().stream().filter(AuthMethod::isExplicit)
                .sorted(Comparator.comparing(AuthMethod::getName)).collect(Collectors.toList());

    }

    private ResponseData generateSuccessResponse(AuthPolicyDecision decision, RequestParsingInfo parsingInfo,
                                                 UserSession userSession) throws SamlException {

        if (parsingInfo.getProtocolType() == ProtocolType.SAML) {
            return samlService.generateSuccessResponse(decision, parsingInfo, userSession);
        } else {
            return oauthService.generateSuccessResponse(parsingInfo, userSession);
        }
    }
}
