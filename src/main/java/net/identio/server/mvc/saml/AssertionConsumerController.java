/*
 This file is part of Ident.io.

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
package net.identio.server.mvc.saml;

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
import org.springframework.web.util.HtmlUtils;

import net.identio.server.exceptions.ServerException;
import net.identio.server.exceptions.ValidationException;
import net.identio.server.model.SamlAuthentication;
import net.identio.server.model.State;
import net.identio.server.model.ValidationResult;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.validation.ValidationService;
import net.identio.server.utils.HttpUtils;

@Controller
public class AssertionConsumerController {

	private static final Logger LOG = LoggerFactory.getLogger(AssertionConsumerController.class);

	@Autowired
	private ValidationService validationService;

	@Autowired
	private ConfigurationService configurationService;

	@Autowired
	private ResponderController responderController;

	@RequestMapping(value = "/SAML2/ACS/POST", method = RequestMethod.POST)
	public String samlConsumerPost(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			@RequestParam("SAMLResponse") String usSamlResponse,
			@RequestParam(value = "RelayState", required = false) String usRelayState,
			@CookieValue String identioSession) throws ValidationException, ServerException {

		LOG.debug("Received SAML response on /SAML2/ACS/POST");
		LOG.debug("* SAMLResponse: {}", usSamlResponse);
		LOG.debug("* RelayState: {}", usRelayState);

		// To prevent XSS attacks, we escape the RelayState value
		String decodedRelayState = HtmlUtils.htmlEscape(usRelayState);
		SamlAuthentication authentication = new SamlAuthentication(usSamlResponse);

		ValidationResult result = validationService.validateExplicitAuthentication(decodedRelayState, identioSession,
				null, authentication);

		if (result.getState() == State.RESPONSE) {

			String responseView = responderController.displayResponderPage(
					result.getArValidationResult().getResponseUrl(), result.getResponseData(),
					result.getArValidationResult().getRelayState(), result.getSessionId(), httpResponse);
			return responseView;

		} else {
			LOG.debug("Displaying authentication page");

			HttpUtils.setSessionCookie(httpResponse, result.getSessionId(),
					configurationService.getConfiguration().getGlobalConfiguration().isSecure());

			return "redirect:/#!/auth/" + result.getTransactionId();
		}

	}
}
