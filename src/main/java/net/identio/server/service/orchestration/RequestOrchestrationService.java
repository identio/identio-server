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

import net.identio.server.exceptions.SamlException;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.model.*;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.authpolicy.model.AuthPolicyDecision;
import net.identio.server.service.authpolicy.model.AuthPolicyDecisionStatus;
import net.identio.server.service.oauth.OAuthService;
import net.identio.server.service.orchestration.exceptions.ValidationException;
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

import java.util.ArrayList;
import java.util.HashSet;

@Service
public class RequestOrchestrationService {

    private static final Logger LOG = LoggerFactory.getLogger(RequestOrchestrationService.class);

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private SamlService samlService;

    @Autowired
    private OAuthService oauthService;

    @Autowired
    private UserSessionService userSessionService;

    @Autowired
    private AuthPolicyService authPolicyService;

    public RequestValidationResult validateRequest(InboundRequest request, String sessionId)
            throws ServerException, ValidationException {

        RequestValidationResult validationResult = new RequestValidationResult();

        // Validate the request
        RequestParsingInfo parsingInfo = parseRequest(request);

        switch (parsingInfo.getStatus()) {

            case FATAL_ERROR:
                throw new ValidationException(parsingInfo.getErrorStatus());

            case RESPONSE_ERROR:
                try {
                    return validationResult.setValidationStatus(ValidationStatus.RESPONSE)
                            .setResponseData(generateErrorResponse(parsingInfo));
                } catch (SamlException e) {
                    throw new ServerException(OrchestrationErrorStatus.SERVER_ERROR);
                }

        }

        TransactionData transactionData = transactionService.createTransaction();
        UserSession userSession = userSessionService.getUserSession(sessionId);
        transactionData.setUserSession(userSession);
        transactionData.setProtocolType(parsingInfo.getProtocolType());

        validationResult.setTransactionId(transactionData.getTransactionId());
        validationResult.setSessionId(userSession.getId());

        // Determine target auth levels and auth methods
        ArrayList<AuthLevel> targetAuthLevels = authPolicyService.determineTargetAuthLevel(parsingInfo);
        HashSet<AuthMethod> targetAuthMethods = authPolicyService.determineTargetAuthMethods(targetAuthLevels);

        // Check if previous authentications match
        AuthPolicyDecision decision = authPolicyService.checkPreviousAuthSessions(userSession, targetAuthLevels);

        if (decision.getStatus() == AuthPolicyDecisionStatus.OK) {

            try {

                validationResult.setValidationStatus(ValidationStatus.RESPONSE)
                        .setResponseData(generateSuccessResponse(decision, parsingInfo, userSession));

            } catch (SamlException e) {
                throw new ServerException(OrchestrationErrorStatus.SERVER_ERROR);
            } finally {
                transactionService.removeTransactionData(transactionData);
            }


        } else {

            validationResult.setValidationStatus(ValidationStatus.AUTH);

            // Save data that will need later in the transaction
            transactionData.setState(TransactionState.AUTH);
            transactionData.setRequestParsingInfo(parsingInfo);
            transactionData.setTargetAuthLevels(targetAuthLevels);
            transactionData.setTargetAuthMethods(targetAuthMethods);
        }

        return validationResult;
    }

    private RequestParsingInfo parseRequest(InboundRequest request) {

        if (request instanceof SamlInboundRequest) {
            return samlService.validateAuthentRequest((SamlInboundRequest) request);
        } else {
            return oauthService.validateAuthentRequest((OAuthInboundRequest) request);
        }
    }

    private ResponseData generateErrorResponse(RequestParsingInfo parsingInfo) throws SamlException {

        if (parsingInfo.getProtocolType() == ProtocolType.SAML) {
            return samlService.generateErrorResponse(parsingInfo);
        } else {
            return oauthService.generateErrorResponse(parsingInfo);
        }
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
