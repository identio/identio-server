package net.identio.server.mvc.oauth.model;

public class ConsentResponse {

    private boolean success;
    private String response;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }
}
