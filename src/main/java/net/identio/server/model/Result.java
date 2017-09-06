package net.identio.server.model;

public class Result<T> {

    private T result;
    private String errorStatus;

    public Result(T result, String errorStatus) {
        this.result = result;
        this.errorStatus = errorStatus;
    }

    public Result(T result) {
        this.result = result;
    }

    public T get() {
        return result;
    }

    public boolean isSuccess() {
        return errorStatus == null;
    }

    public String getErrorStatus() {
        return errorStatus;
    }
}
