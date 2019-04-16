export enum AuthenticationResponseStatus {
    Response = 'RESPONSE',
    Error = 'ERROR',
    Consent = 'CONSENT',
    Challenge = 'CHALLENGE'
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

export class AuthenticationResponse {

    status: AuthenticationResponseStatus;
    responseData: ResponseData;
    protocolType: ProtocolType;
    errorStatus: string;
    challengeType: string;
    challengeValue: string;
}
