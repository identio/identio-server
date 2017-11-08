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

import net.identio.server.model.Result;
import net.identio.server.mvc.oauth.model.OAuthApiErrorResponse;
import net.identio.server.service.oauth.TokenIntrospectionService;
import net.identio.server.service.oauth.model.OAuthToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class IntrospectionController {

    @Autowired
    private TokenIntrospectionService tokenIntrospectionService;

    @PostMapping(value = "/oauth/introspect")
    public ResponseEntity<?> introspect(@RequestParam(value = "token", required = false) String token,
                                        @RequestParam(value = "token_type_hint", required = false) String tokenType,
                                        @RequestHeader(value = "Authorization", required = false) String authorization) {


        Result<OAuthToken> result = tokenIntrospectionService.getTokenInformations(token, tokenType, authorization);

        switch(result.getResultStatus()) {
            case FAIL:
                return new ResponseEntity<>(
                        new OAuthApiErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.BAD_REQUEST);
            default:
            case SERVER_ERROR:
                return new ResponseEntity<>(
                        new OAuthApiErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.INTERNAL_SERVER_ERROR);
            case UNAUTHORIZED:
                return new ResponseEntity<>(
                        new OAuthApiErrorResponse().setError(result.getErrorStatus()),
                        HttpStatus.UNAUTHORIZED);
            case OK:
                return new ResponseEntity<>(result.get(), HttpStatus.OK);

        }

    }
}
