package org.codelibs.elasticsearch.auth.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.codelibs.elasticsearch.auth.filter.ContentFilter;
import org.codelibs.elasticsearch.auth.logic.LoginLogic;
import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;

public class AuthService extends AbstractLifecycleComponent<AuthService> {
    private RestController restController;

    private Map<String, Authenticator> authenticatorMap = new HashMap<String, Authenticator>();

    @Inject
    public AuthService(final Settings settings, final Client client,
            final RestController restController) {
        super(settings);
        this.restController = restController;

        logger.info("Creating authenticators.");

    }

    @Override
    protected void doStart() throws ElasticSearchException {
        logger.info("START AuthService");

        final List<LoginLogic> loginLogicList = new ArrayList<LoginLogic>();
        final Map<String, Settings> loginSettings = settings
                .getGroups("auth.login");
        for (final Map.Entry<String, Settings> entry : loginSettings.entrySet()) {
            final Settings name = entry.getValue();
            final Settings params = entry.getValue();
            final String[] paths = params.getAsArray("paths", new String[0]);
            final String[] roles = params.getAsArray("roles", new String[0]);
            final String auth = params.get("auth");
            final Authenticator authenticator = authenticatorMap.get(auth);
            if (paths.length > 0 && roles.length > 0 && authenticator != null) {
                final LoginLogic loginLogic = new LoginLogic();
                loginLogic.setName(name);
                loginLogic.setPaths(paths);
                loginLogic.setRoles(roles);
                loginLogic.setAuthenticator(authenticator);
                loginLogicList.add(loginLogic);
            } else {
                logger.info("Invaid login settings: " + name);
            }
        }

        if (!loginLogicList.isEmpty()) {
            final ContentFilter contentFilter = new ContentFilter(
                    loginLogicList.toArray(new LoginLogic[loginLogicList.size()]));
            restController.registerFilter(contentFilter);
        }
    }

    @Override
    protected void doStop() throws ElasticSearchException {
        logger.info("STOP AuthService");

        // TODO Your code..
    }

    @Override
    protected void doClose() throws ElasticSearchException {
        logger.info("CLOSE AuthService");

        // TODO Your code..
    }

    public void registerAuthenticator(final String name,
            final Authenticator authenticator) {
        authenticatorMap.put(name, authenticator);
    }
}
