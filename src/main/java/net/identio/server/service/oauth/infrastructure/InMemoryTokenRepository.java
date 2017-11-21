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

package net.identio.server.service.oauth.infrastructure;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import net.identio.server.service.oauth.infrastructure.exceptions.TokenCreationException;
import net.identio.server.service.oauth.infrastructure.exceptions.TokenDeleteException;
import net.identio.server.service.oauth.infrastructure.exceptions.TokenFetchException;
import net.identio.server.service.oauth.model.OAuthToken;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class InMemoryTokenRepository implements TokenRepository {

    private LoadingCache<String, OAuthToken> tokenCache;

    public InMemoryTokenRepository() {

        tokenCache = CacheBuilder.newBuilder().maximumSize(100000).expireAfterAccess(1, TimeUnit.HOURS)
                .build(new CacheLoader<String, OAuthToken>() {
                    public OAuthToken load(@Nonnull String o) {
                        return new OAuthToken();
                    }
                });
    }

    @Override
    public void save(OAuthToken rt) throws TokenCreationException {

        tokenCache.put(rt.getValue(), rt);
    }

    @Override
    public Optional<OAuthToken> getTokenByValue(String tokenValue, String type) throws TokenFetchException {

        Optional<OAuthToken> result = getTokenByValue(tokenValue);

        if (result.isPresent() && type.equals(result.get().getType())) {
            return result;
        }
        else
            return Optional.empty();
    }

    @Override
    public Optional<OAuthToken> getTokenByValue(String refreshTokenValue) throws TokenFetchException {

        OAuthToken result = tokenCache.getIfPresent(refreshTokenValue);

        return result != null ? Optional.of(result) : Optional.empty();
    }

    @Override
    public void delete(String refreshTokenValue) throws TokenDeleteException {

        tokenCache.invalidate(refreshTokenValue);
    }
}
