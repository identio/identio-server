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
package net.identio.server.service.orchestration.model;

import net.identio.saml.Endpoint;

public class SamlAuthRequestGenerationResult {

    private boolean success;
    private String errorStatus;
    private Endpoint targetEndpoint;
    private String serializedRequest;
    private String relayState;
    private String signature;
    private String signatureAlgorithm;

    public boolean isSuccess() {
        return success;
    }

    public SamlAuthRequestGenerationResult setSuccess(boolean success) {
        this.success = success;
        return this;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public SamlAuthRequestGenerationResult setErrorStatus(String errorStatus) {
        this.errorStatus = errorStatus;
        return this;
    }

    public Endpoint getTargetEndpoint() {
        return targetEndpoint;
    }

    public SamlAuthRequestGenerationResult setTargetEndpoint(Endpoint targetEndpoint) {
        this.targetEndpoint = targetEndpoint;
        return this;
    }

    public String getSerializedRequest() {
        return serializedRequest;
    }

    public SamlAuthRequestGenerationResult setSerializedRequest(String serializedRequest) {
        this.serializedRequest = serializedRequest;
        return this;
    }

    public String getRelayState() {
        return relayState;
    }

    public SamlAuthRequestGenerationResult setRelayState(String relayState) {
        this.relayState = relayState;
        return this;
    }

    public String getSignature() {
        return signature;
    }

    public SamlAuthRequestGenerationResult setSignature(String signature) {
        this.signature = signature;
        return this;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public SamlAuthRequestGenerationResult setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }
}
