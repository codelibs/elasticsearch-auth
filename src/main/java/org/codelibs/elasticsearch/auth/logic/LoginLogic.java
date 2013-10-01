package org.codelibs.elasticsearch.auth.logic;

import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.rest.RestRequest;

public class LoginLogic {
    private static final ESLogger logger = Loggers.getLogger(LoginLogic.class);

    private String path;

    private String[] roles;

    private Authenticator authenticator;

    public void setName(final String name) {
    }

    public void setPath(final String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public void setRoles(final String[] roles) {
        this.roles = roles;
    }

    public void setAuthenticator(final Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    public boolean match(final String rawPath) {
        return rawPath.startsWith(path);
    }

    public boolean authenticate(final RestRequest request) {
        return authenticator.authenticate(request, roles);
    }

}
