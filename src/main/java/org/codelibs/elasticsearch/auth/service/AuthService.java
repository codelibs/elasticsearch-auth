package org.codelibs.elasticsearch.auth.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.codelibs.elasticsearch.auth.filter.ContentFilter;
import org.codelibs.elasticsearch.auth.filter.LoginFilter;
import org.codelibs.elasticsearch.auth.logic.LoginLogic;
import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest.Method;

public class AuthService extends AbstractLifecycleComponent<AuthService> {
    private RestController restController;

    private Map<String, Authenticator> authenticatorMap = new LinkedHashMap<String, Authenticator>();

    @Inject
    public AuthService(final Settings settings, final Client client,
            final RestController restController) {
        super(settings);
        this.restController = restController;

        logger.info("Creating authenticators.");

    }

    @Override
    protected void doStart() throws ElasticSearchException {
        logger.info("Starting AuthService.");

        final List<LoginLogic> loginLogicList = new ArrayList<LoginLogic>();
        final Map<String, Settings> securitySettings = settings
                .getGroups("auth.security");
        for (final Map.Entry<String, Settings> entry : securitySettings
                .entrySet()) {
            final String name = entry.getKey();
            final Settings params = entry.getValue();
            final String[] paths = params.getAsArray("paths", new String[0]);
            final String[] roles = params.getAsArray("roles", new String[0]);
            final String auth = params.get("auth");
            final Authenticator authenticator = authenticatorMap.get(auth);
            if (paths.length > 0 && roles.length > 0 && authenticator != null) {
                for (final String path : paths) {
                    final LoginLogic loginLogic = new LoginLogic();
                    loginLogic.setName(name);
                    loginLogic.setPath(path);
                    loginLogic.setRoles(roles);
                    loginLogic.setAuthenticator(authenticator);
                    loginLogicList.add(loginLogic);
                }
            } else {
                logger.info("Invaid login settings: " + name);
            }
        }

        if (!loginLogicList.isEmpty()) {
            String loginPath = settings.get("auth.login.path");
            if (loginPath == null) {
                loginPath = "/login";
            }
            Method[] methods;
            final String[] methodValues = settings
                    .getAsArray("auth.login.methods");
            if (methodValues == null) {
                methods = new Method[] { Method.POST };
            } else {
                final List<Method> methodList = new ArrayList<Method>();
                for (final String method : methodValues) {
                    if ("get".equalsIgnoreCase(method)) {
                        methodList.add(Method.GET);
                    } else if ("post".equalsIgnoreCase(method)) {
                        methodList.add(Method.POST);
                    } else if ("head".equalsIgnoreCase(method)) {
                        methodList.add(Method.HEAD);
                    } else if ("options".equalsIgnoreCase(method)) {
                        methodList.add(Method.OPTIONS);
                    } else if ("put".equalsIgnoreCase(method)) {
                        methodList.add(Method.PUT);
                    } else if ("delete".equalsIgnoreCase(method)) {
                        methodList.add(Method.DELETE);
                    }
                }
                methods = methodList.toArray(new Method[methodList.size()]);
            }
            final LoginFilter loginFilter = new LoginFilter(authenticatorMap,
                    methods, loginPath);
            restController.registerFilter(loginFilter);

            Collections.sort(loginLogicList, new Comparator<LoginLogic>() {
                @Override
                public int compare(final LoginLogic o1, final LoginLogic o2) {
                    final String path1 = o1.getPath();
                    final String path2 = o2.getPath();
                    final int length1 = path1.length();
                    final int length2 = path2.length();
                    if (length1 == length2) {
                        return path1.compareTo(path2) > 0 ? 1 : -1;
                    }
                    return length1 < length2 ? -1 : 1;
                }
            });
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
