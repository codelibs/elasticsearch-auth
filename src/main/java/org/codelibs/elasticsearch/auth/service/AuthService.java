package org.codelibs.elasticsearch.auth.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

import org.apache.commons.codec.digest.DigestUtils;
import org.codelibs.elasticsearch.auth.AuthException;
import org.codelibs.elasticsearch.auth.filter.ContentFilter;
import org.codelibs.elasticsearch.auth.filter.LoginFilter;
import org.codelibs.elasticsearch.auth.filter.LogoutFilter;
import org.codelibs.elasticsearch.auth.security.Authenticator;
import org.codelibs.elasticsearch.auth.security.LoginConstraint;
import org.codelibs.elasticsearch.auth.util.MapUtil;
import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthResponse;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthStatus;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.elasticsearch.action.admin.indices.refresh.RefreshResponse;
import org.elasticsearch.action.delete.DeleteResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.netty.handler.codec.http.Cookie;
import org.elasticsearch.common.netty.handler.codec.http.CookieDecoder;
import org.elasticsearch.common.netty.handler.codec.http.HttpHeaders;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;

public class AuthService extends AbstractLifecycleComponent<AuthService> {
    private static final String DEFAULT_CONSTRAINT_TYPE = "constraint";

    private static final String DEFAULT_CONSTRAINT_INDEX_NAME = "security";

    private static final String DEFAULT_COOKIE_TOKEN_NAME = "eaid";

    private static final String DEFAULT_GUEST_ROLE = "guest";

    private RestController restController;

    private Map<String, Authenticator> authenticatorMap = new LinkedHashMap<String, Authenticator>();

    private Client client;

    private String constraintIndex;

    private String constraintType;

    private String authTokenIndex = "auth";

    private String tokenType = "token";

    private String tokenKey = "token";

    private String guestRole;

    private ContentFilter contentFilter;

    private boolean cookieToken = true;

    private String cookieTokenName;

    private boolean updateToken;

    @Inject
    public AuthService(final Settings settings, final Client client,
            final RestController restController) {
        super(settings);
        this.client = client;
        this.restController = restController;

        logger.info("Creating authenticators.");

        constraintIndex = settings.get("auth.constraint.index",
                DEFAULT_CONSTRAINT_INDEX_NAME);
        constraintType = settings.get("auth.constraint.type",
                DEFAULT_CONSTRAINT_TYPE);
        cookieTokenName = settings.get("auth.token.cookie",
                DEFAULT_COOKIE_TOKEN_NAME);
        updateToken = settings.getAsBoolean("auth.token.update_by_request",
                true);
        guestRole = settings.get("auth.role.guest", DEFAULT_GUEST_ROLE);

        if (cookieTokenName.trim().length() == 0
                || "false".equalsIgnoreCase(cookieTokenName)) {
            cookieToken = false;
        }
    }

    @Override
    protected void doStart() throws ElasticSearchException {
        logger.info("Starting AuthService.");

        final LoginFilter loginFilter = new LoginFilter(this, authenticatorMap);
        final String loginPath = settings.get("auth.login.path");
        if (loginPath != null) {
            loginFilter.setLoginPath(loginPath);
        }
        final String[] loginMethodValues = settings
                .getAsArray("auth.login.methods");
        if (loginMethodValues != null && loginMethodValues.length > 0) {
            loginFilter.setHttpMethods(createMethods(loginMethodValues));
        }
        restController.registerFilter(loginFilter);

        final LogoutFilter logoutFilter = new LogoutFilter(this);
        final String logoutPath = settings.get("auth.logout.path");
        if (logoutPath != null) {
            logoutFilter.setLogoutPath(logoutPath);
        }
        final String[] logoutMethodValues = settings
                .getAsArray("auth.logout.methods");
        if (logoutMethodValues != null && logoutMethodValues.length > 0) {
            logoutFilter.setHttpMethods(createMethods(logoutMethodValues));
        }
        restController.registerFilter(logoutFilter);

        contentFilter = new ContentFilter(this);
        restController.registerFilter(contentFilter);
    }

    @Override
    protected void doStop() throws ElasticSearchException {
        logger.info("Stopping AuthService");
    }

    @Override
    protected void doClose() throws ElasticSearchException {
        logger.info("Closing AuthService.");
    }

    public void registerAuthenticator(final String name,
            final Authenticator authenticator) {
        authenticatorMap.put(name, authenticator);
    }

    public void init(final ActionListener<Void> listener) {
        client.admin().cluster().prepareHealth().setWaitForYellowStatus()
                .execute(new ActionListener<ClusterHealthResponse>() {
                    @Override
                    public void onResponse(final ClusterHealthResponse response) {
                        if (response.getStatus() == ClusterHealthStatus.RED) {
                            listener.onFailure(new AuthException(
                                    RestStatus.SERVICE_UNAVAILABLE,
                                    "This cluster is not ready."));
                        } else {
                            createConstraintIndexIfNotExist(listener);
                        }
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(e);
                    }
                });
    }

    protected void createConstraintIndexIfNotExist(
            final ActionListener<Void> listener) {
        client.admin().indices().prepareExists(constraintIndex)
                .execute(new ActionListener<IndicesExistsResponse>() {
                    @Override
                    public void onResponse(final IndicesExistsResponse response) {
                        if (response.isExists()) {
                            reload(listener);
                        } else {
                            createConstraintIndex(listener);
                        }
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(e);
                    }
                });
    }

    protected void createConstraintIndex(final ActionListener<Void> listener) {
        client.admin().indices().prepareCreate(constraintIndex)
                .execute(new ActionListener<CreateIndexResponse>() {
                    @Override
                    public void onResponse(final CreateIndexResponse response) {
                        // TODO health check
                        reload(listener);
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(e);
                    }
                });
    }

    public void reload(final ActionListener<Void> listener) {
        client.admin().indices().prepareRefresh(constraintIndex).setForce(true)
                .execute(new ActionListener<RefreshResponse>() {
                    @Override
                    public void onResponse(final RefreshResponse response) {
                        loadLoginConstraints(new ActionListener<LoginConstraint[]>() {
                            @Override
                            public void onResponse(
                                    final LoginConstraint[] constraints) {
                                if (logger.isDebugEnabled()) {
                                    logger.debug("Load {} constraint(s).",
                                            constraints.length);
                                }
                                contentFilter.setLoginConstraints(constraints);
                                listener.onResponse(null);
                            }

                            @Override
                            public void onFailure(final Throwable e) {
                                listener.onFailure(e);
                            }
                        });
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(e);
                    }
                });
    }

    public void createToken(final Set<String> roleSet,
            final ActionListener<String> listener) {
        if (roleSet == null || roleSet.isEmpty()) {
            listener.onFailure(new AuthException(RestStatus.BAD_REQUEST,
                    "Role is empty."));
            return;
        }

        final String token = generateToken();

        final Map<String, Object> sourceMap = new HashMap<String, Object>();
        sourceMap.put("roles", roleSet);
        sourceMap.put("lastModified", new Date());
        client.prepareIndex(authTokenIndex, tokenType, token)
                .setSource(sourceMap).setRefresh(true)
                .execute(new ActionListener<IndexResponse>() {
                    @Override
                    public void onResponse(final IndexResponse response) {
                        listener.onResponse(token);
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(e);
                    }
                });
    }

    public void authenticate(final String token, final String[] roles,
            final ActionListener<Boolean> listener) {
        if (token == null) {
            if (roles != null) {
                for (final String role : roles) {
                    if (guestRole.equals(role)) {
                        listener.onResponse(true);
                        return;
                    }
                }
            }
            listener.onResponse(false);
        } else {
            client.prepareGet(authTokenIndex, tokenType, token).execute(
                    new ActionListener<GetResponse>() {
                        @Override
                        public void onResponse(final GetResponse response) {
                            final Map<String, Object> sourceMap = response
                                    .getSource();
                            if (sourceMap != null) {
                                final String[] tokenRoles = MapUtil.getAsArray(
                                        sourceMap, "roles", new String[0]);
                                for (final String role : roles) {
                                    for (final String tokenRole : tokenRoles) {
                                        if (role.equals(tokenRole)) {
                                            listener.onResponse(true);
                                            if (updateToken) {
                                                updateToken(token, sourceMap);
                                            }
                                            return;
                                        }
                                    }
                                }
                            }
                            listener.onResponse(false);
                        }

                        @Override
                        public void onFailure(final Throwable e) {
                            listener.onFailure(e);
                        }
                    });
        }
    }

    private void updateToken(final String token,
            final Map<String, Object> sourceMap) {
        sourceMap.put("lastModified", new Date());
        client.prepareIndex(authTokenIndex, tokenType, token)
                .setSource(sourceMap)
                .execute(new ActionListener<IndexResponse>() {
                    @Override
                    public void onResponse(final IndexResponse response) {
                        // nothing
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        logger.warn("Failed to update token: " + token, e);
                    }
                });
    }

    public void createUser(final String authenticatorName,
            final String username, final String password, final String[] roles,
            final ActionListener<Void> listener) {
        if (authenticatorName == null || username == null || password == null
                || roles == null) {
            listener.onFailure(new AuthException(RestStatus.BAD_REQUEST,
                    "authenticator, username, passowrd or roles is null."));
        } else {
            getAuthenticator(authenticatorName).createUser(username, password,
                    roles, listener);
        }
    }

    public void updateUser(final String authenticatorName,
            final String username, final String password, final String[] roles,
            final ActionListener<Void> listener) {
        if (authenticatorName == null || username == null || password == null
                && roles == null) {
            listener.onFailure(new AuthException(RestStatus.BAD_REQUEST,
                    "authenticator, username, passowrd or roles are null."));
        } else {
            getAuthenticator(authenticatorName).updateUser(username, password,
                    roles, listener);
        }
    }

    public void deleteUser(final String authenticatorName,
            final String username, final ActionListener<Void> listener) {
        if (authenticatorName == null || username == null) {
            listener.onFailure(new AuthException(RestStatus.BAD_REQUEST,
                    "authenticator or username are null."));
        } else {
            getAuthenticator(authenticatorName).deleteUser(username, listener);
        }
    }

    public void deleteToken(final String token,
            final ActionListener<Void> listener) {
        client.prepareDelete(authTokenIndex, tokenType, token).setRefresh(true)
                .execute(new ActionListener<DeleteResponse>() {
                    @Override
                    public void onResponse(final DeleteResponse response) {
                        if (!response.isNotFound()) {
                            listener.onResponse(null);
                        } else {
                            listener.onFailure(new AuthException(
                                RestStatus.BAD_REQUEST,
                                "The token does not exist."));
                        }
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(e);
                    }
                });
    }

    public String getToken(final RestRequest request) {
        String token = request.param(tokenKey);
        //   cookie
        if (token == null && cookieToken) {
            final String cookieString = request
                    .header(HttpHeaders.Names.COOKIE);
            if (cookieString != null) {
                final CookieDecoder cookieDecoder = new CookieDecoder();
                final Set<Cookie> cookies = cookieDecoder.decode(cookieString);
                for (final Cookie cookie : cookies) {
                    if (cookieTokenName.equals(cookie.getName())) {
                        token = cookie.getValue();
                        break;
                    }
                }
            }
        }
        return token;
    }

    private String generateToken() {
        return DigestUtils.sha512Hex(UUID.randomUUID().toString());
    }

    private Authenticator getAuthenticator(final String authenticatorName) {
        final Authenticator authenticator = authenticatorMap
                .get(authenticatorName);
        if (authenticator == null) {
            throw new AuthException(RestStatus.BAD_REQUEST,
                    "Unknown authenticator: " + authenticatorName);
        }
        return authenticator;
    }

    protected void loadLoginConstraints(
            final ActionListener<LoginConstraint[]> listener) {
        client.prepareSearch(constraintIndex).setTypes(constraintType)
                .setQuery(QueryBuilders.queryString("*:*"))
                .execute(new ActionListener<SearchResponse>() {
                    @Override
                    public void onResponse(final SearchResponse response) {
                        final Map<String, LoginConstraint> constraintMap = new TreeMap<String, LoginConstraint>(
                                new Comparator<String>() {
                                    @Override
                                    public int compare(final String path1,
                                            final String path2) {
                                        final int length1 = path1.length();
                                        final int length2 = path2.length();
                                        if (length1 == length2) {
                                            return -1 * path1.compareTo(path2);
                                        }
                                        return length1 < length2 ? -1 : 1;
                                    }
                                });
                        final SearchHits hits = response.getHits();
                        if (hits.totalHits() != 0) {
                            for (final SearchHit hit : hits) {
                                final Map<String, Object> sourceMap = hit
                                        .sourceAsMap();
                                final List<String> methodList = MapUtil
                                        .getAsList(sourceMap, "methods",
                                                Collections
                                                        .<String> emptyList());
                                final List<String> pathList = MapUtil
                                        .getAsList(sourceMap, "paths",
                                                Collections
                                                        .<String> emptyList());
                                final List<String> roleList = MapUtil
                                        .getAsList(sourceMap, "roles",
                                                Collections
                                                        .<String> emptyList());
                                if (!pathList.isEmpty() && !roleList.isEmpty()) {
                                    for (final String path : pathList) {
                                        LoginConstraint constraint = constraintMap
                                                .get(path);
                                        if (constraint == null) {
                                            constraint = new LoginConstraint();
                                            constraint.setPath(path);
                                            constraintMap.put(path, constraint);
                                        }
                                        constraint.addCondition(methodList
                                                .toArray(new String[methodList
                                                        .size()]), roleList
                                                .toArray(new String[roleList
                                                        .size()]));
                                    }
                                } else {
                                    logger.warn("Invaid login settings: "
                                            + sourceMap);
                                }
                            }
                        }

                        listener.onResponse(constraintMap.values().toArray(
                                new LoginConstraint[constraintMap.size()]));
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(new AuthException(
                                RestStatus.INTERNAL_SERVER_ERROR,
                                constraintIndex + ":" + constraintType
                                        + " is not found.", e));
                    }
                });

    }

    private Method[] createMethods(final String[] methodValues) {
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
        return methodList.toArray(new Method[methodList.size()]);
    }

}
