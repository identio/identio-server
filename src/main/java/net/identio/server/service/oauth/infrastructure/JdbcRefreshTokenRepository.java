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

import com.zaxxer.hikari.HikariDataSource;
import net.identio.server.exceptions.InitializationException;
import net.identio.server.service.oauth.infrastructure.exceptions.*;
import net.identio.server.service.oauth.model.RefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

public class JdbcRefreshTokenRepository implements RefreshTokenRepository {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcRefreshTokenRepository.class);

    private HikariDataSource ds;

    public JdbcRefreshTokenRepository(HikariDataSource ds) {

        this.ds = ds;
    }

    @Override
    public void save(RefreshToken rt) throws RefreshTokenCreationException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("INSERT INTO refresh_token (refresh_token, client_id, expires_in, scope, user_id) " +
                    "VALUES (?, ?, ?, ?, ?);");

            creationStatement.setString(1, rt.getValue());
            creationStatement.setString(2, rt.getClientId());
            creationStatement.setInt(3, rt.getExpiresIn());
            creationStatement.setString(4, rt.getScope());
            creationStatement.setString(5, rt.getClientId());

            creationStatement.executeUpdate();

        } catch (SQLException e) {
            LOG.error("Error when inserting refresh token {} in database: {}", rt.getValue(), e.getMessage());
            throw new RefreshTokenCreationException(e);
        }
    }

    @Override
    public Optional<RefreshToken> getAccessTokenByRefreshTokenValue(String refreshTokenValue) throws RefreshTokenFetchException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("SELECT * FROM refresh_token WHERE refresh_token = ?;");

            creationStatement.setString(1, refreshTokenValue);

            ResultSet rs = creationStatement.executeQuery();

            // Fetch
            if (!rs.first()) {
                return Optional.empty();
            } else {
                return Optional.of(
                        new RefreshToken().setValue(refreshTokenValue)
                                .setClientId(rs.getString("client_id"))
                                .setExpiresIn(rs.getInt("expires_in"))
                                .setScope(rs.getString("scope"))
                                .setUserId(rs.getString("user_id"))
                );
            }

        } catch (SQLException e) {
            LOG.error("Error when fetching refresh token {} in database: {}", refreshTokenValue, e.getMessage());
            throw new RefreshTokenFetchException(e);
        }
    }

    @Override
    public void delete(String refreshTokenValue) throws RefreshTokenDeleteException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("DELETE FROM refresh_token WHERE refresh_token = ?;");

            creationStatement.setString(1, refreshTokenValue);

            creationStatement.executeUpdate();

        } catch (SQLException e) {
            LOG.error("Error when inserting refresh token {} in database: {}", refreshTokenValue, e.getMessage());
            throw new RefreshTokenDeleteException(e);
        }
    }
}
