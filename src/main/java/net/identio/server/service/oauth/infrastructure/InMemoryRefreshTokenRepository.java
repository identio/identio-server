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
import net.identio.server.service.oauth.infrastructure.exceptions.RefreshTokenCreationException;
import net.identio.server.service.oauth.infrastructure.exceptions.RefreshTokenDeleteException;
import net.identio.server.service.oauth.infrastructure.exceptions.RefreshTokenFetchException;
import net.identio.server.service.oauth.model.RefreshToken;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class InMemoryRefreshTokenRepository implements RefreshTokenRepository {

    private LoadingCache<String, RefreshToken> refreshTokenCache;

    public InMemoryRefreshTokenRepository() {

        refreshTokenCache = CacheBuilder.newBuilder().maximumSize(100000).expireAfterAccess(1, TimeUnit.MINUTES)
                .build(new CacheLoader<String, RefreshToken>() {
                    public RefreshToken load(@Nonnull String o) {
                        return new RefreshToken();
                    }
                });
    }

    @Override
    public void save(RefreshToken rt) throws RefreshTokenCreationException {

        refreshTokenCache.put(rt.getValue(), rt);
    }

    @Override
    public Optional<RefreshToken> getAccessTokenByRefreshTokenValue(String refreshTokenValue) throws RefreshTokenFetchException {

        RefreshToken result = refreshTokenCache.getIfPresent(refreshTokenValue);

        return result != null ? Optional.of(result) : Optional.empty();
    }

    @Override
    public void delete(String refreshTokenValue) throws RefreshTokenDeleteException {

        refreshTokenCache.invalidate(refreshTokenValue);
    }
}
