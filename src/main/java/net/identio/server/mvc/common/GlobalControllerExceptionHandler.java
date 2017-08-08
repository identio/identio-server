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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import net.identio.server.exceptions.ServerException;
import net.identio.server.exceptions.ValidationException;

@ControllerAdvice
public class GlobalControllerExceptionHandler {

	@Autowired
	private DefaultErrorController errorController;

	@ExceptionHandler(ServerException.class)
	public String handleServerException() {
		return errorController.displayErrorPage("error.server");
	}

	@ExceptionHandler(ValidationException.class)
	public String handleValidationException() {
		return errorController.displayErrorPage("error.validation");
	}
	
	@ExceptionHandler(ServletRequestBindingException.class)
	public String handleServletRequestBindingException() {
		return errorController.displayErrorPage("missing.parameter");
	}
}
