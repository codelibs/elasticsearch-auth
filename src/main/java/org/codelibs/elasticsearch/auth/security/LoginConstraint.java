package org.codelibs.elasticsearch.auth.security;

public class LoginConstraint {

    private String path;

    private String[] roles;

    public void setPath(final String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }

    public void setRoles(final String[] roles) {
        this.roles = roles;
    }

    public String[] getRoles() {
        return roles;
    }

    public boolean match(final String rawPath) {
        return rawPath.startsWith(path);
    }

}
