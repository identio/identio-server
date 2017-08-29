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
package net.identio.server.mvc.common;

import net.identio.server.exceptions.SamlException;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.model.AuthMethod;
import net.identio.server.service.orchestration.model.SamlAuthRequestGenerationResult;
import net.identio.server.mvc.common.model.*;
import net.identio.server.service.authentication.model.UserPasswordAuthentication;
import net.identio.server.service.orchestration.AuthOrchestrationService;
import net.identio.server.service.orchestration.ProxyAuthOrchestrationService;
import net.identio.server.service.orchestration.model.AuthenticationValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

@RestController
public class AuthentController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthentController.class);

    @Autowired
    private AuthOrchestrationService authOrchestrationService;

    @Autowired
    private ProxyAuthOrchestrationService proxyAuthOrchestrationService;

    @RequestMapping(value = "/api/auth/submit/password", method = RequestMethod.POST)
    public AuthSubmitResponse authenticationSubmit(HttpServletRequest httpRequest,
                                                   @RequestBody AuthSubmitRequest authSubmitRequest, HttpServletResponse httpResponse,
                                                   @RequestHeader(value = "X-Transaction-ID") String transactionId,
                                                   @CookieValue("identioSession") String sessionId)
            throws ValidationException, WebSecurityException, ServerException {

        LOG.debug("Received authentication form");
        LOG.debug("* TransactionId: {}", transactionId);

        AuthSubmitResponse response = new AuthSubmitResponse();

        UserPasswordAuthentication authentication = new UserPasswordAuthentication(authSubmitRequest.getLogin(),
                authSubmitRequest.getPassword(), authSubmitRequest.getChallengeResponse());

        AuthenticationValidationResult result = authOrchestrationService
                .handleExplicitAuthentication(transactionId, sessionId, authSubmitRequest.getMethod(), authentication);

        switch (result.getValidationStatus()) {

            case RESPONSE:

                response.setStatus(ApiResponseStatus.RESPONSE)
                        .setResponseData(result.getResponseData())
                        .setProtocolType(result.getProtocolType());
                break;

            case CHALLENGE:

                response.setStatus(ApiResponseStatus.CHALLENGE)
                        .setChallengeType(result.getChallengeType())
                        .setChallengeValue(result.getChallengeValue());
                break;

            case ERROR:

                response.setStatus(ApiResponseStatus.ERROR)
                        .setErrorStatus(result.getErrorStatus());
                break;

            case CONSENT:

                response.setStatus(ApiResponseStatus.CONSENT);
                break;

        }

        return response;
    }

    @RequestMapping(value = "/api/auth/submit/saml", method = RequestMethod.POST)
    public LaunchSamlAuthenticationResponse launchSamlAuthentication(HttpServletRequest httpRequest,
                                                                     @RequestBody AuthSubmitRequest authSubmitRequest, HttpServletResponse httpResponse,
                                                                     @RequestHeader(value = "X-Transaction-ID") String transactionId,
                                                                     @CookieValue("identioSession") String sessionId)
            throws ValidationException, WebSecurityException, ServerException {

        LOG.debug("* Received authentication request to IDP {}", authSubmitRequest.getMethod());

        SamlAuthRequestGenerationResult result = proxyAuthOrchestrationService
                .initSamlRequest(transactionId, sessionId, authSubmitRequest.getMethod());

        if (result.isSuccess()) {
            return new LaunchSamlAuthenticationResponse().setDestinationUrl(result.getTargetEndpoint().getLocation())
                    .setBinding(result.getTargetEndpoint().getBinding()).setRelayState(result.getRelayState())
                    .setSamlRequest(result.getSerializedRequest()).setSigAlg(result.getSignatureAlgorithm())
                    .setSignature(result.getSignature());
        }

        return new LaunchSamlAuthenticationResponse().setErrorStatus(result.getErrorStatus());
    }

    @RequestMapping(value = "/api/auth/methods", method = RequestMethod.GET)
    public List<AuthMethodResponse> getAuthMethods(@RequestHeader(value = "X-Transaction-ID") String transactionId,
                                                   @CookieValue("identioSession") String sessionId)
            throws WebSecurityException {

        LOG.debug("Received authmethods list");

        List<AuthMethodResponse> list = new ArrayList<AuthMethodResponse>();

        for (AuthMethod authMethod : authOrchestrationService.getAuthMethods(transactionId, sessionId)) {
            list.add(new AuthMethodResponse().setName(authMethod.getName()).setType(authMethod.getType()));
        }

        return list;
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(ServerException.class)
    public ApiErrorResponse handleServerException(SamlException e) {
        return new ApiErrorResponse(e.getMessage());
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ValidationException.class)
    public ApiErrorResponse handleValidationException(ValidationException e) {
        return new ApiErrorResponse(e.getMessage());
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(WebSecurityException.class)
    public ApiErrorResponse handleWebSecurityException(WebSecurityException e) {
        return new ApiErrorResponse(e.getMessage());
    }

}
