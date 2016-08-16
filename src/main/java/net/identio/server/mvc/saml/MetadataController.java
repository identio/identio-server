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
package net.identio.server.mvc.saml;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import net.identio.server.exceptions.ServerException;
import net.identio.server.service.saml.MetadataService;

@Controller
public class MetadataController {

	private static final Logger LOG = LoggerFactory.getLogger(MetadataController.class);

	@Autowired
	private MetadataService metadataService;

	@RequestMapping(value = "/SAML2", method = RequestMethod.GET)
	public void getIdpMetadata(HttpServletResponse httpResponse) throws ServerException {

		LOG.debug("Received IDP metadata request...");

		String returnValue = metadataService.getIdpMetadata().toString();

		httpResponse.setContentType("application/samlmetadata+xml");
		httpResponse.setContentLength((int) returnValue.length());
		httpResponse.setHeader("Content-Disposition", "attachment; filename=\"identio-idp-metadata.xml\"");

		try (Writer writer = httpResponse.getWriter();) {
			writer.write(returnValue);
			writer.flush();

		} catch (IOException ex) {
			LOG.error("IOException when generating metadata");
			LOG.debug(" * Detailed Stacktrace:", ex);
			throw new ServerException("IOException when generating metadata", ex);
		}

		LOG.debug("IDP metadata successfully generated");

	}
}
