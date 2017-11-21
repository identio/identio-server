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
import net.identio.server.service.data.JdbcDataService;
import net.identio.server.service.oauth.OAuthConfiguration;
import net.identio.server.service.oauth.infrastructure.exceptions.*;
import net.identio.server.service.oauth.model.OAuthToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.codec.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

public class JdbcTokenRepository implements TokenRepository {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcTokenRepository.class);

    private HikariDataSource ds;

    public JdbcTokenRepository(OAuthConfiguration config, JdbcDataService dataService) {
        this.ds = dataService.getDataSource(config.getDataSource());
    }

    @Override
    public void save(OAuthToken token) throws TokenCreationException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("INSERT INTO tokens" +
                    " (hash, active, value, type, client_id, expiration, issued_at, not_before, scope, username, subject, audience, issuer, jwt_id) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");

            creationStatement.setString(1, hash(token.getValue()));
            creationStatement.setBoolean(2, true);
            creationStatement.setString(3, token.getValue());
            creationStatement.setString(4, token.getType());
            creationStatement.setString(5, token.getClientId());
            creationStatement.setLong(6, token.getExpiration());
            creationStatement.setLong(7, token.getIssuedAt());
            creationStatement.setLong(8, token.getNotBefore());
            creationStatement.setString(9, token.getScope());
            creationStatement.setString(10, token.getUsername());
            creationStatement.setString(11, token.getSubject());
            creationStatement.setString(12, token.getAudience());
            creationStatement.setString(13, token.getIssuer());
            creationStatement.setString(14, token.getJwtId());

            creationStatement.executeUpdate();

        } catch (SQLException e) {
            LOG.error("Error when inserting token {} in database: {}", token.getValue(), e.getMessage());
            throw new TokenCreationException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error when inserting token {} in database: SHA-256 algorithm is not supported", token.getValue());
            throw new TokenCreationException(e);
        }
    }

    @Override
    public Optional<OAuthToken> getTokenByValue(String tokenValue) throws TokenFetchException {
        return getTokenByValue(tokenValue, null);
    }

    @Override
    public Optional<OAuthToken> getTokenByValue(String tokenValue, String type) throws TokenFetchException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement;
            if (type == null) {
                creationStatement = connection.prepareStatement("SELECT * FROM tokens WHERE hash = ?");
            }
            else {
                creationStatement = connection.prepareStatement("SELECT * FROM tokens WHERE hash = ? AND type = ?;");
                creationStatement.setString(2, type);
            }

            creationStatement.setString(1, hash(tokenValue));

            ResultSet rs = creationStatement.executeQuery();

            // Fetch
            if (!rs.first()) {
                return Optional.empty();
            } else {

                return Optional.of(
                        new OAuthToken().setValue(tokenValue)
                                .setType(type)
                                .setActive(rs.getBoolean("active"))
                                .setClientId(rs.getString("client_id"))
                                .setExpiration(rs.getLong("expiration"))
                                .setIssuedAt(rs.getLong("issued_at"))
                                .setNotBefore(rs.getLong("not_before"))
                                .setScope(rs.getString("scope"))
                                .setUsername(rs.getString("username"))
                                .setSubject(rs.getString("subject"))
                                .setAudience(rs.getString("audience"))
                                .setIssuer(rs.getString("issuer"))
                                .setJwtId(rs.getString("jwt_id"))

                );
            }
        } catch (SQLException e) {
            LOG.error("Error when fetching token {} in database: {}", tokenValue, e.getMessage());
            throw new TokenFetchException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error when fetching token {} in database: SHA-256 algorithm is not supported", tokenValue);
            throw new TokenFetchException(e);
        }
    }

    @Override
    public void delete(String tokenValue) throws TokenDeleteException {

        try (Connection connection = this.ds.getConnection()) {

            PreparedStatement creationStatement = connection.prepareStatement("DELETE FROM refresh_token WHERE hash = ?;");

            creationStatement.setString(1, hash(tokenValue));

            creationStatement.executeUpdate();

        } catch (SQLException e) {
            LOG.error("Error when deleting token {} in database: {}", tokenValue, e.getMessage());
            throw new TokenDeleteException(e);
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Error when deleting token {} in database: SHA-256 algorithm is not supported", tokenValue);
            throw new TokenDeleteException(e);
        }
    }

    private String hash(String tokenValue) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update(tokenValue.getBytes());

        return new String(Hex.encode(md.digest()));
    }
}
