package org.codelibs.elasticsearch.auth.rest;

import static org.elasticsearch.rest.RestStatus.OK;

import java.io.IOException;
import java.util.Date;

import org.codelibs.elasticsearch.auth.service.AuthService;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.index.mapper.object.ObjectMapper;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.XContentRestResponse;
import org.elasticsearch.rest.XContentThrowableRestResponse;
import org.elasticsearch.rest.action.support.RestXContentBuilder;

public class AccountRestAction extends BaseRestHandler {

    @Inject
    public AccountRestAction(final Settings settings, final Client client,
            final RestController restController, final AuthService authService) {
        super(settings, client);
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
        try {
            final XContentBuilder builder = RestXContentBuilder
                    .restContentBuilder(request);
            builder.startObject();
            builder.field("index", request.param("index"));
            builder.field("type", request.param("type"));
            builder.field("description", "This is a sample response: "
                    + new Date().toString());
            builder.endObject();
            channel.sendResponse(new XContentRestResponse(request, OK, builder));
        } catch (final IOException e) {
            try {
                channel.sendResponse(new XContentThrowableRestResponse(request,
                        e));
            } catch (final IOException e1) {
                logger.error("Failed to send a failure response.", e1);
            }
        }
    }

}
