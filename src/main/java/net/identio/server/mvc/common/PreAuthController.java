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

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import net.identio.server.exceptions.ServerException;
import net.identio.server.exceptions.ValidationException;
import net.identio.server.model.State;
import net.identio.server.model.ValidationResult;
import net.identio.server.model.X509Authentication;
import net.identio.server.mvc.saml.ResponderController;
import net.identio.server.service.configuration.ConfigurationService;
import net.identio.server.service.validation.ValidationService;
import net.identio.server.utils.HttpUtils;

@Controller
public class PreAuthController {

	private static final Logger LOG = LoggerFactory.getLogger(PreAuthController.class);

	@Autowired
	private ValidationService validationService;
	@Autowired
	private ResponderController responderController;
	@Autowired
	private ConfigurationService configurationService;

	public String checkTransparentAuthentication(HttpServletRequest httpRequest, HttpServletResponse httpResponse,
			ValidationResult result) throws ServerException, ValidationException {

		// We check if the user was authenticated with a X509 certificate
		Object clientAuthCerts = httpRequest.getAttribute("javax.servlet.request.X509Certificate");

		String userCert = HttpUtils.getHttpHeader(httpRequest, "X-User-Cert");
		String sharedSecret = HttpUtils.getHttpHeader(httpRequest, "X-Shared-Secret");

		X509Authentication authentication = null;

		if (clientAuthCerts != null || userCert != null && sharedSecret != null) {
			authentication = new X509Authentication((X509Certificate[]) clientAuthCerts, userCert, sharedSecret);
		}

		ValidationResult validationResult = validationService.validateTransparentAuthentication(result, authentication);

		if (validationResult.getState() == State.RESPONSE) {

			String responseView = responderController.displayResponderPage(
					result.getArValidationResult().getResponseUrl(), result.getResponseData(),
					result.getArValidationResult().getRelayState(), result.getSessionId(), httpResponse);
			return responseView;

		} else {
			LOG.debug("Displaying authentication page");

			HttpUtils.setSessionCookie(httpResponse, result.getSessionId(),
					configurationService.getConfiguration().getGlobalConfiguration().isSecure());

			return "redirect:/#/auth/" + validationResult.getTransactionId();
		}
	}
}
