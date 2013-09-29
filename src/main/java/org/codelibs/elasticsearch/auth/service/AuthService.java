package org.codelibs.elasticsearch.auth.service;

import org.elasticsearch.ElasticSearchException;
import org.elasticsearch.common.component.AbstractLifecycleComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;

public class AuthService extends AbstractLifecycleComponent<AuthService> {

    @Inject
    public AuthService(final Settings settings) {
        super(settings);
        logger.info("CREATE AuthService");

        // TODO Your code..
    }

    @Override
    protected void doStart() throws ElasticSearchException {
        logger.info("START AuthService");

        // TODO Your code..
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

}
