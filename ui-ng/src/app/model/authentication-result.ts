export enum AuthenticationResultStatus {
    Response = 'RESPONSE',
    Error = 'ERROR',
    Consent = 'CONSENT',
    AdditionalAuth = 'ADDITIONAL_AUTH'
}

export enum ProtocolType {
    SAML = 'SAML',
    OAuth = 'OAUTH'
}

export class ResponseData {
    url: string;
    data: string;
    relayState?: string;
}

export class AuthenticationResult {

    status: AuthenticationResultStatus;
    responseData: ResponseData;
    protocolType: ProtocolType;
    errorStatus: string;
}
