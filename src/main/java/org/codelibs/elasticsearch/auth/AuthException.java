package org.codelibs.elasticsearch.auth;

import org.elasticsearch.rest.RestStatus;

public class AuthException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    RestStatus restStatus;

    public AuthException(final RestStatus restStatus, final String message) {
        super(message);
        this.restStatus = restStatus;
    }

    public AuthException(final RestStatus restStatus, final String message,
            final Throwable cause) {
        super(message, cause);
        this.restStatus = restStatus;
    }

    public RestStatus getStatus() {
        return restStatus;
    }

}
