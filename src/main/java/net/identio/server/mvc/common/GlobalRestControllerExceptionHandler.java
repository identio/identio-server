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

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import net.identio.server.exceptions.SamlException;
import net.identio.server.exceptions.ServerException;
import net.identio.server.exceptions.ValidationException;
import net.identio.server.model.api.ApiErrorResponse;

@ControllerAdvice(annotations = RestController.class)
public class GlobalRestControllerExceptionHandler {

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

}
