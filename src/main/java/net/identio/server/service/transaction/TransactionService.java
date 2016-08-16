/*
 This file is part of Ident.io

 Ident.io - A flexible authentication server
 Copyright (C) Loeiz TANGUY

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.identio.server.service.transaction;

import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

import net.identio.server.model.TransactionData;

@Service
@Scope("singleton")
public class TransactionService {

	private static final Logger LOG = LoggerFactory.getLogger(TransactionService.class);

	private LoadingCache<String, TransactionData> transactionCache;

	public TransactionService() {

		transactionCache = CacheBuilder.newBuilder().maximumSize(100000).expireAfterAccess(10, TimeUnit.MINUTES)
				.build(new CacheLoader<String, TransactionData>() {
					public TransactionData load(String o) {
						return new TransactionData();
					}
				});
	}

	public TransactionData createTransaction() {

		LOG.debug("Generating new transaction datas");

		String transactionId = UUID.randomUUID().toString();

		TransactionData data = new TransactionData();
		data.setTransactionId(transactionId);
		transactionCache.put(transactionId, data);

		LOG.debug("New transaction generated {}", transactionId);

		return data;
	}

	public void removeTransactionData(TransactionData transactionData) {

		LOG.debug("Destroyed transaction {}", transactionData.getTransactionId());
		transactionCache.invalidate(transactionData.getTransactionId());
	}

	public TransactionData getTransaction(String transactionId) {

		if (transactionId == null) {
			return new TransactionData();
		}

		LOG.debug("Fetch transaction {} in cache", transactionId);

		try {
			return transactionCache.get(transactionId);
		} catch (ExecutionException e) {
			return new TransactionData();
		}
	}

}
