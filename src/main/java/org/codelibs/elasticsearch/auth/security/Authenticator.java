package org.codelibs.elasticsearch.auth.security;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.rest.RestRequest;

public interface Authenticator {

    void login(RestRequest request, ActionListener<String[]> listener);

    void createUser(String username, String password, String[] roles,
            ActionListener<Void> listener);

    void updateUser(String username, String password, String[] roles,
            ActionListener<Void> listener);

    void deleteUser(String username, ActionListener<Void> listener);

}
