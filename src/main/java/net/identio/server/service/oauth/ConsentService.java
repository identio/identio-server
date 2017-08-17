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

import net.identio.server.service.orchestration.exceptions.ValidationException;
import net.identio.server.service.orchestration.exceptions.WebSecurityException;
import net.identio.server.model.AuthorizationScope;
import net.identio.server.service.transaction.model.TransactionData;
import net.identio.server.mvc.oauth.model.ConsentContext;
import net.identio.server.service.transaction.TransactionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class ConsentService {

    private static final Logger LOG = LoggerFactory.getLogger(ConsentService.class);

    @Autowired
    private TransactionService transactionService;

    public ConsentContext getConsentContext(String transactionId, String sessionId)
            throws WebSecurityException {

        TransactionData transactionData = transactionService.getTransaction(sessionId, transactionId);

        List<AuthorizationScope> authorizedScopes = transactionData
                .getRequestParsingInfo()
                .getRequestedScopes().stream()
                .map(AuthorizationScope::getPublicCopy)
                .collect(Collectors.toList());

        return new ConsentContext().setRequestedScopes(authorizedScopes)
                .setAudience(transactionData.getRequestParsingInfo().getSourceApplicationName())
                .setAudienceLogo("");

    }
}
