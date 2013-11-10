package org.codelibs.elasticsearch.auth.security;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.codelibs.elasticsearch.auth.AuthException;
import org.codelibs.elasticsearch.auth.util.MapUtil;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.delete.DeleteResponse;
import org.elasticsearch.action.get.GetResponse;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.update.UpdateResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentParser;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class IndexAuthenticator implements Authenticator {
    private static final ESLogger logger = Loggers
            .getLogger(IndexAuthenticator.class);;

    protected Client client;

    private String authIndex = "auth";

    private String userType = "user";

    private String usernameKey = "username";

    private String passwordKey = "password";

    public IndexAuthenticator(final Client client) {
        this.client = client;
    }

    @Override
    public void login(final RestRequest request,
            final ActionListener<String[]> listener) {
        String username = request.param(usernameKey);
        String password = request.param(passwordKey);
        final BytesReference content = request.content();
        final XContentType xContentType = XContentFactory.xContentType(content);
        XContentParser parser = null;
        try {
            parser = XContentFactory.xContent(xContentType).createParser(
                    content);
            final XContentParser.Token t = parser.nextToken();
            if (t != null) {
                final Map<String, Object> contentMap = parser.map();
                username = MapUtil.getAsString(contentMap, usernameKey,
                        username);
                password = MapUtil.getAsString(contentMap, passwordKey,
                        password);
            }
        } catch (final Exception e) {
            listener.onFailure(e);
            return;
        } finally {
            if (parser != null) {
                parser.close();
            }
        }

        if (username == null) {
            listener.onResponse(new String[0]);
            return;
        }

        processLogin(username, password, listener);

    }

    private void processLogin(final String username, final String password,
            final ActionListener<String[]> listener) {
        client.prepareGet(authIndex, userType, getUserId(username)).execute(
                new ActionListener<GetResponse>() {

                    @Override
                    public void onResponse(final GetResponse response) {
                        final Map<String, Object> sourceMap = response
                                .getSource();
                        if (sourceMap != null) {
                            final String hash = (String) sourceMap
                                    .get("password");
                            if (hash != null
                                    && hash.equals(hashPassword(password))) {
                                if (logger.isDebugEnabled()) {
                                    logger.debug(sourceMap.get("username")
                                            + " is logged in.");
                                }
                                listener.onResponse(MapUtil.getAsArray(
                                        sourceMap, "roles", new String[0]));
                                return;
                            }
                        }
                        listener.onResponse(new String[0]);
                        return;
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(e);
                    }
                });
    }

    @Override
    public void createUser(final String username, final String password,
            final String[] roles, final ActionListener<Void> listener) {
        try {
            final XContentBuilder builder = jsonBuilder() //
                    .startObject() //
                    .field("username", username) //
                    .field("password", hashPassword(password)) //
                    .field("roles", roles) //
                    .endObject();
            client.prepareIndex(authIndex, userType, getUserId(username))
                    .setSource(builder).setRefresh(true)
                    .execute(new ActionListener<IndexResponse>() {
                        @Override
                        public void onResponse(final IndexResponse response) {
                            listener.onResponse(null);
                        }

                        @Override
                        public void onFailure(final Throwable e) {
                            listener.onFailure(new AuthException(
                                    RestStatus.INTERNAL_SERVER_ERROR,
                                    "Could not create " + username, e));
                        }
                    });
        } catch (final Exception e) {
            listener.onFailure(new AuthException(
                    RestStatus.INTERNAL_SERVER_ERROR, "Could not create "
                            + username, e));
        }
    }

    @Override
    public void updateUser(final String username, final String password,
            final String[] roles, final ActionListener<Void> listener) {
        try {
            final XContentBuilder builder = jsonBuilder().startObject()
                    .field("doc").startObject();
            if (password != null) {
                builder.field("password", hashPassword(password));
            }
            if (roles != null) {
                builder.field("roles", roles);
            }
            builder.endObject().endObject();
            final String userId = getUserId(username);
            client.prepareUpdate(authIndex, userType, userId)
                    .setSource(builder).setRefresh(true)
                    .execute(new ActionListener<UpdateResponse>() {

                        @Override
                        public void onResponse(final UpdateResponse response) {
                            if (!userId.equals(response.getId())) {
                                listener.onFailure(new AuthException(
                                        RestStatus.BAD_REQUEST,
                                        "Could not update " + username));
                            } else {
                                listener.onResponse(null);
                            }
                        }

                        @Override
                        public void onFailure(final Throwable e) {
                            listener.onFailure(new AuthException(
                                    RestStatus.INTERNAL_SERVER_ERROR,
                                    "Could not update " + username, e));
                        }
                    });

        } catch (final Exception e) {
            listener.onFailure(new AuthException(
                    RestStatus.INTERNAL_SERVER_ERROR, "Could not update "
                            + username, e));
        }

    }

    @Override
    public void deleteUser(final String username,
            final ActionListener<Void> listener) {
        client.prepareDelete(authIndex, userType, getUserId(username))
                .setRefresh(true).execute(new ActionListener<DeleteResponse>() {

                    @Override
                    public void onResponse(final DeleteResponse response) {
                        if (response.isNotFound()) {
                            listener.onFailure(new AuthException(
                                    RestStatus.BAD_REQUEST, "Could not delete "
                                            + username));
                        } else {
                            listener.onResponse(null);
                        }
                    }

                    @Override
                    public void onFailure(final Throwable e) {
                        listener.onFailure(new AuthException(
                                RestStatus.INTERNAL_SERVER_ERROR,
                                "Could not delete " + username, e));
                    }
                });

    }

    protected String getUserId(final String username) {
        return DigestUtils.sha512Hex(username);
    }

    protected String hashPassword(final String password) {
        if (password == null) {
            return "";
        }
        return DigestUtils.sha512Hex(password);
    }

    public void setIndex(final String index) {
        authIndex = index;
    }

    public void setType(final String type) {
        userType = type;
    }

}
