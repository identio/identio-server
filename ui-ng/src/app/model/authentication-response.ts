export enum AuthenticationResponseStatus {
    Response = "RESPONSE",
    Error = "ERROR",
    Consent = "CONSENT",
    Challenge = "CHALLENGE"
}

export class ResponseData {
    url: string;
    data: string;
    relayState?: string;
}

export class AuthenticationResponse {

    status: AuthenticationResponseStatus;
    responseData: ResponseData;
    protocolType: string;
    errorStatus: string;
    challengeType: string;
    challengeValue: string;
}