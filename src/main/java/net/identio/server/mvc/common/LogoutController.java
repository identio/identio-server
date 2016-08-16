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
package net.identio.server.mvc.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import net.identio.server.service.usersession.UserSessionService;

@Controller
public class LogoutController {

	private static final Logger LOG = LoggerFactory.getLogger(LogoutController.class);

	@Autowired
	private UserSessionService userSessionService;

	@RequestMapping(value = "/logout", method = RequestMethod.GET)
	public String logout(@CookieValue("identioSession") String sessionId) {

		LOG.info("Received logout request for session {}", sessionId);

		userSessionService.removeUserSession(sessionId);

		return "redirect:/#/logout";
	}
}
