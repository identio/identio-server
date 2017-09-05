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
package net.identio.server.mvc.oauth;

import net.identio.server.mvc.common.model.ApiErrorResponse;
import net.identio.server.service.orchestration.exceptions.ServerException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.mvc.oauth.model.ConsentContext;
import net.identio.server.mvc.oauth.model.ConsentRequest;
import net.identio.server.mvc.oauth.model.ConsentResponse;
import net.identio.server.service.oauth.ConsentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class ConsentController {

    @Autowired
    private ConsentService consentService;

    @RequestMapping(value = "/api/authz/consent", method = RequestMethod.GET)
    public ConsentContext getConsentContext(@RequestHeader(value = "X-Transaction-ID") String transactionId,
                                            @CookieValue("identioSession") String sessionId)
            throws WebSecurityException {


        return consentService.getConsentContext(transactionId, sessionId);
    }

    @RequestMapping(value = "/api/authz/consent", method = RequestMethod.POST)
    public ConsentResponse receiveConsent(@RequestBody ConsentRequest consentRequest,
                                          @RequestHeader(value = "X-Transaction-ID") String transactionId,
                                          @CookieValue("identioSession") String sessionId) throws WebSecurityException, ServerException {

        return consentService.validateConsent(consentRequest, transactionId, sessionId);
    }

    @ResponseStatus(HttpStatus.FORBIDDEN)
    @ExceptionHandler(WebSecurityException.class)
    public ApiErrorResponse handleWebSecurityException(WebSecurityException e) {
        return new ApiErrorResponse(e.getMessage());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(WebSecurityException.class)
    public ApiErrorResponse handleServerException(ServerException e) {
        return new ApiErrorResponse(e.getMessage());
    }
}
