package org.codelibs.elasticsearch.auth.rest;

import java.util.Map;

import org.codelibs.elasticsearch.auth.AuthException;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.MapUtil;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
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
import org.elasticsearch.rest.RestRequest.Method;
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
    public void handleRequest(final RestRequest request,
            final RestChannel channel) {
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

        try {
            if (request.method() == Method.PUT) {
                if (authenticator == null || username == null
                        || password == null || roles == null) {
                    ResponseUtil
                            .send(request, channel, RestStatus.BAD_REQUEST,
                                    "message",
                                    "authenticator, username, passowrd or roles is null.");
                } else {
                    authService.createUser(authenticator, username, password,
                            roles);
                    ResponseUtil.send(request, channel, RestStatus.OK);
                }
            } else if (request.method() == Method.POST) {
                if (authenticator == null || username == null) {
                    ResponseUtil
                            .send(request, channel, RestStatus.BAD_REQUEST,
                                    "message",
                                    "authenticator, username, passowrd or roles are null.");
                } else {
                    authService.updateUser(authenticator, username, password,
                            roles);
                    ResponseUtil.send(request, channel, RestStatus.OK);
                }
            } else if (request.method() == Method.DELETE) {
                if (authenticator == null || username == null
                        || password == null || roles == null) {
                    ResponseUtil.send(request, channel, RestStatus.BAD_REQUEST,
                            "message", "authenticator or username are null.");
                } else {
                    authService.deleteUser(authenticator, username);
                    ResponseUtil.send(request, channel, RestStatus.OK);
                }
            } else {
                ResponseUtil
                        .send(request, channel, RestStatus.BAD_REQUEST,
                                "message", "Invalid method: "
                                        + request.method().name());
            }
        } catch (final AuthException e) {
            logger.error("An operation failed.", e);
            ResponseUtil.send(request, channel, e.getStatus(), "message",
                    e.getMessage());
        } catch (final Exception e) {
            logger.error("An operation failed.", e);
            ResponseUtil
                    .send(request, channel, RestStatus.INTERNAL_SERVER_ERROR,
                            "message", e.getMessage());
        }

    }

}
