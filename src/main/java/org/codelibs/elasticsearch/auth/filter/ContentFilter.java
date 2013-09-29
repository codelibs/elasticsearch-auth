package org.codelibs.elasticsearch.auth.filter;

import org.codelibs.elasticsearch.auth.logic.LoginLogic;
import org.elasticsearch.rest.RestChannel;
import org.elasticsearch.rest.RestFilter;
import org.elasticsearch.rest.RestFilterChain;
import org.elasticsearch.rest.RestRequest;

public class ContentFilter extends RestFilter {

    private LoginLogic[] loginLogics;

    public ContentFilter(final LoginLogic[] loginLogics) {
        this.loginLogics = loginLogics;
    }

    @Override
    public void process(final RestRequest request, final RestChannel channel,
            final RestFilterChain filterChain) {
        final String rawPath = request.rawPath();
        for (final LoginLogic loginLogic : loginLogics) {
            if (loginLogic.match(rawPath)) {
                if (loginLogic.authenticate(request)) {
                    // ok
                    break;
                } else {
                    // invalid
                    return;
                }
            }
        }
        filterChain.continueProcessing(request, channel);
    }

}
