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

package net.identio.server.service.saml;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "samlIdp")
public class SamlConfiguration implements InitializingBean {

    private static final int DEFAULT_TOKEN_VALIDITY_LENGTH = 3;
    private static final String DEFAULT_SP_METADATA_DIRECTORY = "config/trusted-sp";

    // Configuration mapping handled by Spring Cloud config

    private String organizationName;
    private String organizationDisplayName;
    private String organizationUrl;
    private String contactPersonSurname;
    private String contactPersonEmail;
    private boolean allowUnsecureRequests;
    private boolean certificateCheckEnabled;
    private int tokenValidityLength;
    private int allowedTimeOffset;
    private String spMetadataDirectory;

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getOrganizationDisplayName() {
        return organizationDisplayName;
    }

    public void setOrganizationDisplayName(String organizationDisplayName) {
        this.organizationDisplayName = organizationDisplayName;
    }

    public String getOrganizationUrl() {
        return organizationUrl;
    }

    public void setOrganizationUrl(String organizationUrl) {
        this.organizationUrl = organizationUrl;
    }

    public String getContactPersonSurname() {
        return contactPersonSurname;
    }

    public void setContactPersonSurname(String contactPersonSurname) {
        this.contactPersonSurname = contactPersonSurname;
    }

    public String getContactPersonEmail() {
        return contactPersonEmail;
    }

    public void setContactPersonEmail(String contactPersonEmail) {
        this.contactPersonEmail = contactPersonEmail;
    }

    public boolean isAllowUnsecureRequests() {
        return allowUnsecureRequests;
    }

    public void setAllowUnsecureRequests(boolean allowUnsecureRequests) {
        this.allowUnsecureRequests = allowUnsecureRequests;
    }

    public boolean isCertificateCheckEnabled() {
        return certificateCheckEnabled;
    }

    public void setCertificateCheckEnabled(boolean certificateCheckEnabled) {
        this.certificateCheckEnabled = certificateCheckEnabled;
    }

    public int getTokenValidityLength() {
        return tokenValidityLength;
    }

    public void setTokenValidityLength(int tokenValidityLength) {
        this.tokenValidityLength = tokenValidityLength;
    }

    public int getAllowedTimeOffset() {
        return allowedTimeOffset;
    }

    public void setAllowedTimeOffset(int allowedTimeOffset) {
        this.allowedTimeOffset = allowedTimeOffset;
    }

    public String getSpMetadataDirectory() {
        return spMetadataDirectory;
    }

    public void setSpMetadataDirectory(String spMetadataDirectory) {
        this.spMetadataDirectory = spMetadataDirectory;
    }

    // End: Configuration mapping handled by Spring Cloud config

    @Override
    public void afterPropertiesSet() throws Exception {

        tokenValidityLength = tokenValidityLength != 0 ? tokenValidityLength : DEFAULT_TOKEN_VALIDITY_LENGTH;
        spMetadataDirectory = spMetadataDirectory != null ? spMetadataDirectory : DEFAULT_SP_METADATA_DIRECTORY;

    }
}
