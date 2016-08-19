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
package net.identio.server.mvc.common;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import net.identio.server.exceptions.SamlException;
import net.identio.server.exceptions.ServerException;
import net.identio.server.exceptions.ValidationException;
import net.identio.server.model.AuthMethod;
import net.identio.server.model.SamlAuthRequestGenerationResult;
import net.identio.server.model.State;
import net.identio.server.model.UserPasswordAuthentication;
import net.identio.server.model.ValidationResult;
import net.identio.server.model.api.ApiErrorResponse;
import net.identio.server.model.api.AuthMethodResponse;
import net.identio.server.model.api.AuthSubmitRequest;
import net.identio.server.model.api.AuthSubmitResponse;
import net.identio.server.model.api.LaunchSamlAuthenticationResponse;
import net.identio.server.service.validation.ValidationService;

@RestController
public class AuthentController {

	private static final Logger LOG = LoggerFactory.getLogger(AuthentController.class);

	@Autowired
	private ValidationService validationService;

	@RequestMapping(value = "/api/auth/submit/password", method = RequestMethod.POST)
	public AuthSubmitResponse authenticationSubmit(HttpServletRequest httpRequest,
			@RequestBody AuthSubmitRequest authSubmitRequest, HttpServletResponse httpResponse,
			@RequestHeader(value = "X-Transaction-ID") String transactionId,
			@CookieValue("identioSession") String sessionId) throws ValidationException {

		LOG.debug("Received authentication form");
		LOG.debug("* TransactionId: {}", transactionId);

		UserPasswordAuthentication authentication = new UserPasswordAuthentication(authSubmitRequest.getLogin(),
				authSubmitRequest.getPassword(), authSubmitRequest.getChallengeResponse());

		ValidationResult result = validationService.validateExplicitAuthentication(transactionId, sessionId,
				authSubmitRequest.getMethod(), authentication);

		if (result.getState() == State.RESPONSE) {

			return new AuthSubmitResponse().setState(State.RESPONSE)
					.setDestinationUrl(result.getArValidationResult().getResponseUrl())
					.setRelayState(result.getArValidationResult().getRelayState())
					.setSamlResponse(result.getResponseData());
		}

		// Default response: authentication failed
		return new AuthSubmitResponse().setState(result.getState()).setChallengeType(result.getChallengeType())
				.setChallengeValue(result.getChallengeValue()).setErrorStatus(result.getErrorStatus());
	}

	@RequestMapping(value = "/api/auth/submit/saml", method = RequestMethod.POST)
	public LaunchSamlAuthenticationResponse launchSamlAuthentication(HttpServletRequest httpRequest,
			@RequestBody AuthSubmitRequest authSubmitRequest, HttpServletResponse httpResponse,
			@RequestHeader(value = "X-Transaction-ID") String transactionId,
			@CookieValue("identioSession") String sessionId) throws ValidationException {

		LOG.debug("* Received authentication request to IDP {}", authSubmitRequest.getMethod());

		SamlAuthRequestGenerationResult result = validationService.initSamlRequest(transactionId, sessionId,
				authSubmitRequest.getMethod());

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
			@CookieValue("identioSession") String sessionId) throws ValidationException {

		LOG.debug("Received authmethods list");

		List<AuthMethodResponse> list = new ArrayList<AuthMethodResponse>();

		for (AuthMethod authMethod : validationService.getAuthMethods(transactionId, sessionId)) {
			list.add(new AuthMethodResponse().setName(authMethod.getName()).setType(authMethod.getType()));
		}

		return list;
	}

	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	@ExceptionHandler(ServerException.class)
	public ApiErrorResponse handleServerException(SamlException e) {
		return new ApiErrorResponse("error.server", e.getMessage());
	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(ValidationException.class)
	public ApiErrorResponse handleValidationException(ValidationException e) {
		return new ApiErrorResponse("error.validation", e.getMessage());
	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(ServletRequestBindingException.class)
	public ApiErrorResponse handleServletRequestBindingException(ServletRequestBindingException e) {
		return new ApiErrorResponse("error.mssing.parameter", e.getMessage());
	}
	
}
