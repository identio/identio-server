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

import net.identio.server.model.*;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.model.Authentication;
import net.identio.server.service.authentication.model.AuthenticationResult;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.authpolicy.model.AuthPolicyDecision;
import net.identio.server.service.authpolicy.model.AuthPolicyDecisionStatus;
import net.identio.server.service.oauth.OAuthResponseService;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.service.saml.SamlService;
import net.identio.server.service.transaction.model.TransactionData;
import net.identio.server.service.transaction.TransactionService;
import net.identio.server.service.transaction.model.TransactionState;
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
    private SamlService samlService;

    @Autowired
    private OAuthResponseService oAuthResponseService;

    @Autowired
    private AuthPolicyService authPolicyService;

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private AuthenticationService authenticationService;

    public AuthenticationValidationResult handleTransparentAuthentication(Authentication authentication, String sessionId,
                                                                          String transactionId)
            throws WebSecurityException, ServerException {

        LOG.debug("Check for transparent authentication");

        TransactionData transactionData = transactionService.getTransaction(sessionId, transactionId);

        AuthenticationResult authResult = authenticationService.validateTransparent(authentication);

        return decideResponse(authResult, transactionData);
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

        // Try to map the auth method name to a known method
        Result<AuthMethod> authMethod = authenticationService.getAuthMethodByName(authMethodName);

        if (!authMethod.isSuccess())
            return AuthenticationValidationResult.error(OrchestrationErrorStatus.AUTH_METHOD_NOT_ALLOWED);

        if (!authPolicyService.checkAllowedAuthMethods(transactionData.getTargetAuthMethods(), authMethod.get())) {

            transactionService.removeTransactionData(transactionData);
            return AuthenticationValidationResult.error(OrchestrationErrorStatus.AUTH_METHOD_NOT_ALLOWED);
        }

        AuthenticationResult authResult = authenticationService.validateExplicit(authMethod.get(), authentication);

        return decideResponse(authResult, transactionData);
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

    private Result<ResponseData> generateSuccessResponse(AuthPolicyDecision decision, RequestParsingInfo parsingInfo,
                                                         UserSession userSession) {

        if (parsingInfo.getProtocolType() == ProtocolType.SAML) {
            return samlService.generateSuccessResponse(decision, parsingInfo, userSession);
        } else {
            return oAuthResponseService.generateSuccessResponse(parsingInfo, userSession);
        }
    }

    private AuthenticationValidationResult decideResponse(AuthenticationResult authResult, TransactionData transactionData) throws ServerException {

        AuthenticationValidationResult validationResult = new AuthenticationValidationResult();

        switch (authResult.getStatus()) {

            case SUCCESS:

                AuthPolicyDecision decision = authPolicyService.checkAuthPolicyCompliance(
                        transactionData.getUserSession(), authResult, transactionData.getTargetAuthLevels());

                if (decision.getStatus() == AuthPolicyDecisionStatus.OK) {

                    if (transactionData.getRequestParsingInfo().isConsentNeeded()) {

                        transactionData.setState(TransactionState.CONSENT);
                        return AuthenticationValidationResult.consent(transactionData.getTransactionId());

                    } else {

                        Result<ResponseData> successResponse = generateSuccessResponse(
                                decision,
                                transactionData.getRequestParsingInfo(),
                                transactionData.getUserSession());

                        transactionService.removeTransactionData(transactionData);

                        if (!successResponse.isSuccess())
                            return AuthenticationValidationResult.error(OrchestrationErrorStatus.SERVER_ERROR);

                        return AuthenticationValidationResult.response(successResponse.get());
                    }

                }
                break;

            case FAIL:
                return AuthenticationValidationResult.error(authResult.getErrorStatus());

            case CHALLENGE:
                return AuthenticationValidationResult.challenge(transactionData.getTransactionId(), authResult.getChallengeType(), authResult.getChallengeValue());
        }

        return validationResult;
    }
}
