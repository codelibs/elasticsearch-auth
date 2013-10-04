package org.codelibs.elasticsearch.auth.security;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

import java.util.Map;

import org.apache.commons.codec.digest.DigestUtils;
import org.codelibs.elasticsearch.auth.AuthException;
import org.codelibs.elasticsearch.auth.util.MapUtil;
import org.elasticsearch.action.delete.DeleteResponse;
import org.elasticsearch.action.get.GetResponse;
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
    public String[] login(final RestRequest request) {
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
            logger.error("Could not parse the content.", e);
            return null;
        } finally {
            if (parser != null) {
                parser.close();
            }
        }

        if (username == null) {
            return null;
        }

        final GetResponse response = client
                .prepareGet(authIndex, userType, getUserId(username)).execute()
                .actionGet();
        final Map<String, Object> sourceMap = response.getSource();
        if (sourceMap != null) {
            final String hash = (String) sourceMap.get("password");
            if (hash != null && hash.equals(hashPassword(password))) {
                if (logger.isDebugEnabled()) {
                    logger.debug(sourceMap.get("username") + " is logged in.");
                }
                return MapUtil.getAsArray(sourceMap, "roles", new String[0]);
            }
        }
        return null;
    }

    @Override
    public void createUser(final String username, final String password,
            final String[] roles) {
        try {
            final XContentBuilder builder = jsonBuilder() //
                    .startObject() //
                    .field("username", username) //
                    .field("password", hashPassword(password)) //
                    .field("roles", roles) //
                    .endObject();
            client.prepareIndex(authIndex, userType, getUserId(username))
                    .setSource(builder).setRefresh(true).execute().actionGet();
        } catch (final Exception e) {
            throw new AuthException(RestStatus.INTERNAL_SERVER_ERROR,
                    "Could not create " + username, e);
        }
    }

    @Override
    public void updateUser(final String username, final String password,
            final String[] roles) {
        try {
            final XContentBuilder builder = jsonBuilder() //
                    .startObject();
            if (password != null) {
                builder.field("password", hashPassword(password));
            }
            if (roles != null) {
                builder.field("roles", roles);
            }
            builder.endObject();
            final UpdateResponse response = client
                    .prepareUpdate(authIndex, userType, getUserId(username))
                    .setSource(builder).setRefresh(true).execute().actionGet();
            if (response.getGetResult().isExists()) {
                throw new AuthException(RestStatus.BAD_REQUEST,
                        "Could not update " + username);
            }
        } catch (final AuthException e) {
            throw e;
        } catch (final Exception e) {
            throw new AuthException(RestStatus.INTERNAL_SERVER_ERROR,
                    "Could not update " + username, e);
        }

    }

    @Override
    public void deleteUser(final String username) {
        try {
            final DeleteResponse response = client
                    .prepareDelete(authIndex, userType, getUserId(username))
                    .setRefresh(true).execute().actionGet();
            if (response.isNotFound()) {
                throw new AuthException(RestStatus.BAD_REQUEST,
                        "Could not delete " + username);
            }
        } catch (final AuthException e) {
            throw e;
        } catch (final Exception e) {
            throw new AuthException(RestStatus.INTERNAL_SERVER_ERROR,
                    "Could not delete " + username, e);
        }
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
