package net.identio.server.service.oauth.model;

public class ValidateTokenResult {

    private ValidateTokenStatus status;
    private String errorStatus;

    public ValidateTokenStatus getStatus() {
        return status;
    }

    public ValidateTokenResult setStatus(ValidateTokenStatus status) {
        this.status = status;
        return this;
    }

    public String getErrorStatus() {
        return errorStatus;
    }

    public ValidateTokenResult setErrorStatus(String errorStatus) {
        this.errorStatus = errorStatus;
        return this;
    }
}
