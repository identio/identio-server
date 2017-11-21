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
package net.identio.server.mvc.saml;

import net.identio.server.boot.GlobalConfiguration;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.utils.HttpUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;

@Controller
public class ResponderController {

    private static final Logger LOG = LoggerFactory.getLogger(ResponderController.class);

    @Autowired
    private GlobalConfiguration config;

    public String displayResponderPage(String destinationUrl, String responseData, String relayState, String sessionId,
                                       HttpServletResponse httpResponse) throws ServerException {

        LOG.info("Generation of a SAML Response");

        HttpUtils.setSessionCookie(httpResponse, sessionId, config.isSecure());

        String responseForm = "<!DOCTYPE html><html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"><meta http-equiv=\"Cache-Control\" content=\"no-store, no-cache, must-revalidate\"><meta http-equiv=\"Pragma\" content=\"no-cache\"><meta http-equiv=\"Expires\" content=\"0\"><title>Ident.io SAML Responder</title></head><body><form id=\"responseForm\" method=\"POST\" action=\""
                + destinationUrl + "\"><input type=\"hidden\" name=\"SAMLResponse\" value=\"" + responseData
                + "\"><input type=\"hidden\" name=\"RelayState\" value=\"" + (relayState == null ? "" : relayState)
                + "\"></form><script type=\"text/javascript\">window.onload = function() {document.getElementById(\"responseForm\").submit();};</script></body></html>";

        httpResponse.setContentType("text/html");

        try (Writer writer = httpResponse.getWriter()) {
            writer.write(responseForm);
            writer.flush();

        } catch (IOException ex) {
            LOG.error("IOException when generating response form");
            LOG.debug(" * Detailed Stacktrace:", ex);
            throw new ServerException("IOException when generating response form", ex);
        }

        return null;
    }
}
