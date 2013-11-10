package org.codelibs.elasticsearch.auth.rest;

import org.codelibs.elasticsearch.auth.service.AuthService;
import org.codelibs.elasticsearch.auth.util.ResponseUtil;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestStatus;

public class ReloadRestAction extends BaseRestHandler {

    private AuthService authService;

    @Inject
    public ReloadRestAction(final Settings settings, final Client client,
            final RestController restController, final AuthService authService) {
        super(settings, client);
        this.authService = authService;

        restController.registerHandler(RestRequest.Method.POST,
                "/_auth/reload", this);
    }

    @Override
    public void handleRequest(final RestRequest request,
            final RestChannel channel) {

        authService.reload(new ActionListener<Void>() {
            @Override
            public void onResponse(final Void response) {
                ResponseUtil.send(request, channel, RestStatus.OK);
            }

            @Override
            public void onFailure(final Throwable e) {
                ResponseUtil.send(request, channel,
                        RestStatus.INTERNAL_SERVER_ERROR, "message",
                        "Failed to reload AuthService.");
            }
        });
    }
}
