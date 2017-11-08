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

package net.identio.server.service.oauth;

import net.identio.server.model.Result;
import net.identio.server.service.oauth.infrastructure.OAuthActorsRepository;
import net.identio.server.service.oauth.infrastructure.TokenRepository;
import net.identio.server.service.oauth.infrastructure.exceptions.TokenFetchException;
import net.identio.server.service.oauth.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TokenIntrospectionService {

    private static final String ACCESS_TOKEN_TYPE = "access_token";
    private static final String REFRESH_TOKEN_TYPE = "refresh_token";

    @Autowired
    private OAuthActorsRepository actorsRepository;

    @Autowired
    private TokenRepository tokenRepository;

    public Result<OAuthToken> getTokenInformations(String token, String tokenType, String authorization) {

        if (!actorsRepository.getResourceServerFromAuthorization(authorization).isSuccess()) {
            return Result.unauthorized(OAuthErrors.INVALID_CLIENT);
        }

        return fetchTokenInformations(token, tokenType);
    }

    private Result<OAuthToken> fetchTokenInformations(String token, String tokenType) {


        if (token == null) return Result.fail(OAuthErrors.INVALID_REQUEST);

        Optional<OAuthToken> result;

        try {

            if (tokenType == null)
                result = tokenRepository.getTokenByValue(token);
            else {
                switch (tokenType) {

                    case ACCESS_TOKEN_TYPE:
                        result = tokenRepository.getTokenByValue(token, OAuthToken.BEARER_TOKEN_TYPE);
                        break;

                    case REFRESH_TOKEN_TYPE:
                        result = tokenRepository.getTokenByValue(token, OAuthToken.REFRESH_TOKEN_TYPE);
                        break;

                    default:
                        return Result.fail(OAuthErrors.INVALID_REQUEST);
                }
            }

        } catch (TokenFetchException e) {
            return Result.serverError();
        }

        if (result.isPresent()) {

            OAuthToken fetchedToken = result.get();

            // Ignore check if the token doesn't expire
            if (fetchedToken.getExpiration() != 0 &&
                    fetchedToken.getExpiration() < System.currentTimeMillis() / 1000)
                return Result.success(new OAuthToken().setActive(false));

            return Result.success(fetchedToken);

        } else {
            return Result.success(new OAuthToken().setActive(false));
        }
    }
}
