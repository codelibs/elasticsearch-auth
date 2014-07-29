package org.codelibs.elasticsearch.auth.rest;

import java.util.Map;

import org.codelibs.elasticsearch.auth.AuthException;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.MapUtil;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class AccountRestAction extends BaseRestHandler {

    private AuthService authService;

    @Inject
    public AccountRestAction(final Settings settings, final Client client,
            final RestController restController, final AuthService authService) {
        super(settings, client);
        this.authService = authService;

        restController.registerHandler(RestRequest.Method.POST,
                "/_auth/account", this);
        restController.registerHandler(RestRequest.Method.PUT,
                "/_auth/account", this);
        restController.registerHandler(RestRequest.Method.DELETE,
                "/_auth/account", this);
    }

    @Override
    protected void handleRequest(final RestRequest request,
            final RestChannel channel, final Client client) {
        final BytesReference content = request.content();
        final XContentType xContentType = XContentFactory.xContentType(content);
        XContentParser parser = null;
        String authenticator = null;
        String username = null;
        String password = null;
        String[] roles = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(
                    content);
            final XContentParser.Token t = parser.nextToken();
            if (t != null) {
                final Map<String, Object> contentMap = parser.map();
                authenticator = MapUtil.getAsString(contentMap,
                        "authenticator", null);
                username = MapUtil.getAsString(contentMap, "username", null);
                password = MapUtil.getAsString(contentMap, "password", null);
                roles = MapUtil.getAsArray(contentMap, "roles", new String[0]);
            }
        } catch (final Exception e) {
            logger.error("Could not parse the content.", e);
            ResponseUtil.send(request, channel, RestStatus.BAD_REQUEST,
                    "message", "Could not parse the content.");
            return;
        } finally {
            if (parser != null) {
                parser.close();
            }
        }

        processRequest(request, channel, authenticator, username, password,
                roles);

    }

    private void processRequest(final RestRequest request,
            final RestChannel channel, final String authenticator,
            final String username, final String password, final String[] roles) {
        switch (request.method()) {
        case PUT:
            authService.createUser(authenticator, username, password, roles,
                    new ActionListener<Void>() {

                        @Override
                        public void onResponse(final Void response) {
                            ResponseUtil.send(request, channel, RestStatus.OK);
                        }

                        @Override
                        public void onFailure(final Throwable e) {
                            logger.error("Failed to create " + username, e);
                            if (e instanceof AuthException) {
                                ResponseUtil.send(request, channel,
                                        (AuthException) e);
                            } else {
                                ResponseUtil.send(request, channel,
                                        RestStatus.INTERNAL_SERVER_ERROR,
                                        "message", "Could not create "
                                                + username);
                            }
                        }
                    });
            break;
        case POST:
            authService.updateUser(authenticator, username, password, roles,
                    new ActionListener<Void>() {
                        @Override
                        public void onResponse(final Void response) {
                            ResponseUtil.send(request, channel, RestStatus.OK);
                        }

                        @Override
                        public void onFailure(final Throwable e) {
                            logger.error("Failed to update " + username, e);
                            if (e instanceof AuthException) {
                                ResponseUtil.send(request, channel,
                                        (AuthException) e);
                            } else {
                                ResponseUtil.send(request, channel,
                                        RestStatus.INTERNAL_SERVER_ERROR,
                                        "message", "Could not update "
                                                + username);
                            }
                        }
                    });
            break;
        case DELETE:
            authService.deleteUser(authenticator, username,
                    new ActionListener<Void>() {

                        @Override
                        public void onResponse(final Void response) {
                            ResponseUtil.send(request, channel, RestStatus.OK);
                        }

                        @Override
                        public void onFailure(final Throwable e) {
                            logger.error("Failed to delete " + username, e);
                            if (e instanceof AuthException) {
                                ResponseUtil.send(request, channel,
                                        (AuthException) e);
                            } else {
                                ResponseUtil.send(request, channel,
                                        RestStatus.INTERNAL_SERVER_ERROR,
                                        "message", "Could not delete "
                                                + username);
                            }
                        }
                    });
            break;
        default:
            ResponseUtil.send(request, channel, RestStatus.BAD_REQUEST,
                    "message", "Invalid method: " + request.method().name());
            break;
        }
    }

}
