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
package net.identio.server.mvc.oauth;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import net.identio.server.exceptions.ServerException;
import net.identio.server.exceptions.ValidationException;
import net.identio.server.model.OAuthInboundRequest;
import net.identio.server.model.ValidationResult;
import net.identio.server.mvc.common.PreAuthController;
import net.identio.server.service.validation.ValidationService;

@Controller
public class OAuthController {

	private static final Logger LOG = LoggerFactory.getLogger(OAuthController.class);

	@Autowired
	private ValidationService validationService;
	@Autowired
	private PreAuthController preAuthController;
	
	@RequestMapping(value = "/oauth/authorize", method = RequestMethod.GET)
	public String authorizeRequest(@RequestParam("response_type") String responseType,
			@RequestParam("client_id") String clientId,
			@RequestParam(value = "redirect_uri", required = false) String redirectUri,
			@RequestParam(value = "scope", required = false) String scopes,
			@RequestParam(value = "state", required = false) String state,
			@CookieValue(required = false) String identioSession,
			HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws ValidationException, ServerException {

		LOG.info("Received OAuth authorization request from ClientId: {}", clientId);
		LOG.debug("RT: {} - RU: {} - SC: {} - ST: {}", responseType, redirectUri, scopes, state);

		// Scopes are separated by a space
		List<String> scopesArray = Arrays.asList(scopes.split(" "));

		OAuthInboundRequest request = new OAuthInboundRequest(clientId, responseType, redirectUri, scopesArray, state);

		ValidationResult result = validationService.validateAuthentRequest(request, identioSession);

		switch (result.getState()) {
		case RESPONSE:
			return "redirect:" + result.getResponseData();

		case CONSENT:
			return "redirect:/#/consent/";
			
		default:
			return preAuthController.checkTransparentAuthentication(httpRequest, httpResponse, result);
		}
	}

}
