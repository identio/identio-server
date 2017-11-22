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
import net.identio.server.model.AuthMethod;
import net.identio.server.model.ProtocolType;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.model.Authentication;
import net.identio.server.service.authentication.model.ProxyAuthContext;
import net.identio.server.service.authentication.saml.SamlAuthMethod;
import net.identio.server.service.authentication.saml.SamlAuthentication;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.service.orchestration.model.AuthenticationValidationResult;
import net.identio.server.service.orchestration.model.SamlAuthRequestGenerationResult;
import net.identio.server.service.transaction.model.TransactionData;
import net.identio.server.service.authentication.saml.SamlAuthenticationProvider;
import net.identio.server.service.authpolicy.AuthPolicyService;
import net.identio.server.service.transaction.TransactionService;
import net.identio.server.service.orchestration.model.OrchestrationErrorStatus;
import net.identio.server.service.transaction.model.TransactionState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class ProxyAuthOrchestrationService {

    private static final Logger LOG = LoggerFactory.getLogger(ProxyAuthOrchestrationService.class);

    @Autowired
    private AuthPolicyService authPolicyService;

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private SamlAuthenticationProvider samlAuthenticationProvider;

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private AuthOrchestrationService authOrchestrationService;

    public SamlAuthRequestGenerationResult initSamlRequest(String transactionId, String sessionId,
                                                           String authMethodName)
            throws ValidationException, WebSecurityException, ServerException {

        LOG.debug("Start generation of a SAML request");

        TransactionData transactionData = transactionService.getTransaction(sessionId, transactionId);

        // Check that we are in the correct transaction state
        if (transactionData.getState() != TransactionState.AUTH) {

            transactionService.removeTransactionData(transactionData);
            throw new WebSecurityException(OrchestrationErrorStatus.INVALID_TRANSACTION);
        }

        try {
            AuthMethod authMethod = authenticationService.getAuthMethodByName(authMethodName);

            transactionData.setSelectedAuthMethod(authMethod);

            authPolicyService.checkAllowedAuthMethods(transactionData.getTargetAuthMethods(), authMethod);

            SamlAuthRequestGenerationResult result = samlAuthenticationProvider.initRequest((SamlAuthMethod) authMethod,
                    transactionData.getTargetAuthLevels(), transactionId);

            transactionData.setSamlProxyRequestId(result.getRequestId());

            return result;

        } catch (UnknownAuthMethodException e) {
            throw new ValidationException(OrchestrationErrorStatus.AUTH_METHOD_UNKNOWN);
        } catch (AuthMethodNotAllowedException e) {
            throw new ValidationException(OrchestrationErrorStatus.AUTH_METHOD_NOT_ALLOWED);
        } catch (SamlException e) {
            throw new ServerException(OrchestrationErrorStatus.SERVER_ERROR);
        } finally {
            transactionService.removeTransactionData(transactionData);
        }
    }

    public AuthenticationValidationResult handleProxyAuthentication(String sessionId, ProtocolType protocol, Authentication authentication, String relayState) throws WebSecurityException, ServerException, ValidationException {

        ProxyAuthContext context;

        // Send the state to the proxy auth method to get the transactionId, authentication method and
        switch (protocol) {
            case SAML:
                context = samlAuthenticationProvider.getContextFromRelayState(relayState);
                ((SamlAuthentication) authentication).setRequestId(context.getRequestId());
                break;

            default:
                throw new ServerException(OrchestrationErrorStatus.SERVER_ERROR);
        }

        AuthenticationValidationResult result = authOrchestrationService.handleExplicitAuthentication(context.getTransactionId(), sessionId, context.getAuthMethodName(), authentication);
        result.setTransactionId(context.getTransactionId());

        return result;
    }
}
