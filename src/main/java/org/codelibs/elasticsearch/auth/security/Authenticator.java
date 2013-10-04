package org.codelibs.elasticsearch.auth.security;

import org.elasticsearch.rest.RestRequest;

public interface Authenticator {

    String[] login(RestRequest request);

    void createUser(String username, String password, String[] roles);

    void updateUser(String username, String password, String[] roles);

    void deleteUser(String username);

}
