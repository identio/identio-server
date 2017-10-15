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
package net.identio.server.service.authentication.radius;

import net.identio.server.model.*;
import net.identio.server.service.authentication.AuthenticationProvider;
import net.identio.server.service.authentication.AuthenticationService;
import net.identio.server.service.authentication.model.*;
import net.identio.server.service.transaction.model.TransactionData;
import net.identio.server.utils.DecodeUtils;
import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.RadiusClient;
import net.sourceforge.jradiusclient.RadiusPacket;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import net.sourceforge.jradiusclient.exception.RadiusException;
import net.sourceforge.jradiusclient.packets.PapAccessRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.DataFormatException;

@Service
@Scope("singleton")
public class RadiusAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(RadiusAuthenticationProvider.class);

    private int currentHostIndex;

    @Autowired
    public RadiusAuthenticationProvider(RadiusAuthenticationProviderConfiguration config,
                                        AuthenticationService authenticationService) {

        List<RadiusAuthMethod> authMethods = config.getAuthMethods();

        if (authMethods == null || authMethods.size() == 0)
            return;

        LOG.debug("Initializing Radius Authentication Service");

        for (RadiusAuthMethod radiusAuthMethod : authMethods) {

            LOG.debug("* Data Source: {}", radiusAuthMethod.getName());

        }

        register(authMethods, authenticationService);

        LOG.info("* Radius Authentication Service initialized");

    }

    public AuthenticationResult validate(AuthMethod authMethod, Authentication authentication,
                                         TransactionData transactionData) {

        RadiusAuthMethod radiusAuthMethod = (RadiusAuthMethod) authMethod;
        UserPasswordAuthentication userPwAuthentication = (UserPasswordAuthentication) authentication;

        String userId = userPwAuthentication.getUserId();
        String password = userPwAuthentication.getPassword();
        String challengeResponse = userPwAuthentication.getChallengeResponse();

        try {
            return authenticate(radiusAuthMethod, userId, password, challengeResponse);
        } catch (RadiusException e) {
            try {
                LOG.error("Error when contacting RadiusServer server {}",
                        radiusAuthMethod.getRadiusHost().get(currentHostIndex));

                if (radiusAuthMethod.getRadiusHost().size() > 1) {
                    // Try another server if available
                    currentHostIndex = currentHostIndex < radiusAuthMethod.getRadiusHost().size() - 1
                            ? currentHostIndex + 1 : 0;

                    LOG.error("Switching to Radius server {}", radiusAuthMethod.getRadiusHost().get(currentHostIndex));
                }

                return authenticate(radiusAuthMethod, userId, password, challengeResponse);
            } catch (RadiusException ex) {
                LOG.error("An error occurend when authenticating user");
                return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
                        .setErrorStatus(AuthenticationErrorStatus.TECHNICAL_ERROR);
            }
        }
    }

    private AuthenticationResult authenticate(RadiusAuthMethod radiusAuthMethod, String userId, String password,
                                              String challenge) throws RadiusException {

        try {

            RadiusClient client = new RadiusClient(radiusAuthMethod.getRadiusHost().get(currentHostIndex),
                    radiusAuthMethod.getAuthPort(), radiusAuthMethod.getAccountPort(),
                    radiusAuthMethod.getSharedSecret(), radiusAuthMethod.getTimeout());

            RadiusPacket accessRequest = new PapAccessRequest(userId, password);

            if (challenge != null) {
                accessRequest.setAttribute(deserializeAttribute(challenge));
            }

            // Send access request
            RadiusPacket accessResponse = client.authenticate(accessRequest);

            if (accessResponse.getPacketType() == RadiusPacket.ACCESS_ACCEPT) {

                LOG.info("User {} successfully authenticated with {}", userId, radiusAuthMethod.getName());
                return new AuthenticationResult().setStatus(AuthenticationResultStatus.SUCCESS).setUserId(userId)
                        .setAuthMethod(radiusAuthMethod).setAuthLevel(radiusAuthMethod.getAuthLevel());
            }

            if (accessResponse.getPacketType() == RadiusPacket.ACCESS_CHALLENGE) {

                String message = new String(
                        accessResponse.getAttribute(RadiusAttributeValues.REPLY_MESSAGE).getValue());

                String radiusState = serializeAttribute(accessResponse.getAttribute(RadiusAttributeValues.STATE));
                String challengeType = null;

                LOG.debug("Received challenge: {}", message);

                // We have to parse the reply message from the radius server to
                // know what to do

                // Next token mode
                if (message.contains("enter the new tokencode")) {

                    LOG.debug("Radius server asked for the next token code");
                    challengeType = "RADIUS_NEXT_TOKEN";
                }
                // Next passcode
                if (message.contains("enter the new passcode")) {

                    LOG.debug("Radius server asked for the next passcode");
                    challengeType = "RADIUS_NEXT_PASSCODE";
                }
                // New PIN mode
                if (message.contains("Enter a new PIN")) {
                    LOG.debug("Radius server asked for a new PIN");
                    challengeType = "RADIUS_NEW_PIN";
                }

                return new AuthenticationResult().setStatus(AuthenticationResultStatus.CHALLENGE)
                        .setChallengeType(challengeType).setChallengeValue(radiusState).setUserId(userId);
            }

            if (accessResponse.getPacketType() == RadiusPacket.ACCESS_REJECT) {

                if (accessResponse.hasAttribute(RadiusAttributeValues.REPLY_MESSAGE)) {
                    String message = new String(
                            accessResponse.getAttribute(RadiusAttributeValues.REPLY_MESSAGE).getValue());

                    LOG.error("Authentication failed for user {} with {}: {}", userId, radiusAuthMethod.getName(),
                            message);
                } else {
                    LOG.error("Authentication failed for user {} with {}", userId, radiusAuthMethod.getName());
                }
                new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
                        .setErrorStatus(AuthenticationErrorStatus.INVALID_CREDENTIALS);
            }

        } catch (InvalidParameterException | IOException | DataFormatException ex) {
            LOG.error("Error when contacting RadiusServer server {}",
                    radiusAuthMethod.getRadiusHost().get(currentHostIndex));
        }

        return new AuthenticationResult().setStatus(AuthenticationResultStatus.FAIL)
                .setErrorStatus(AuthenticationErrorStatus.TECHNICAL_ERROR);
    }

    private RadiusAttribute deserializeAttribute(String data)
            throws IOException, DataFormatException, InvalidParameterException {


        byte[] dataBytes = DecodeUtils.decode(data, false);

        int type = dataBytes[0];

        int valueLength = dataBytes.length - 2; // HEADER_LENGTH = 2
        byte[] valueBytes = new byte[valueLength];
        System.arraycopy(dataBytes, 2, valueBytes, 0, valueLength);

        return new RadiusAttribute(type, valueBytes);
    }

    private String serializeAttribute(RadiusAttribute attribute) throws InvalidParameterException, IOException {

        int type = attribute.getType();
        byte[] value = attribute.getValue();

        byte[] data;

        int length = 2 + value.length;// 2 bytes header
        try (ByteArrayOutputStream temp = new ByteArrayOutputStream(length)) {
            temp.write(type);
            temp.write(length);
            temp.write(value);
            temp.flush();
            data = temp.toByteArray();
        } catch (IOException ex) {
            throw new InvalidParameterException("Error constructing RadiusAttribute");
        }

        return DecodeUtils.encode(data, false);
    }

    private void register(List<RadiusAuthMethod> authMethods, AuthenticationService authenticationService) {

        for (RadiusAuthMethod authMethod : authMethods) {

            LOG.debug("* Registering authentication method {}", authMethod.getName());

            authenticationService.registerExplicit(authMethod, this);
        }
    }

    @Override
    public boolean accepts(Authentication authentication) {
        return authentication instanceof UserPasswordAuthentication;
    }
}
