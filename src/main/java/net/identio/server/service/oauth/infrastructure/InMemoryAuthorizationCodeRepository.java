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
import net.identio.server.service.oauth.infrastructure.exceptions.AuthorizationCodeDeleteException;
import net.identio.server.service.oauth.model.AuthorizationCode;

import javax.annotation.Nonnull;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

public class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepository {

    private LoadingCache<String, AuthorizationCode> authorizationCodeCache;

    public InMemoryAuthorizationCodeRepository() {

        authorizationCodeCache = CacheBuilder.newBuilder().maximumSize(100000).expireAfterAccess(1, TimeUnit.MINUTES)
                .build(new CacheLoader<String, AuthorizationCode>() {
                    public AuthorizationCode load(@Nonnull String o) {
                        return new AuthorizationCode();
                    }
                });
    }

    @Override
    public void save(AuthorizationCode code) {

        authorizationCodeCache.put(code.getCode(), code);
    }

    @Override
    public Optional<AuthorizationCode> getAuthorizationCodeByValue(String code) {

        AuthorizationCode result = authorizationCodeCache.getIfPresent(code);

        return result != null ? Optional.of(result) : Optional.empty();
    }

    @Override
    public void delete(AuthorizationCode code) throws AuthorizationCodeDeleteException {

        authorizationCodeCache.invalidate(code);
    }
}
