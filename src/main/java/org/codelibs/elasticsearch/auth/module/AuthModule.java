package org.codelibs.elasticsearch.auth.module;

import org.codelibs.elasticsearch.auth.service.AuthService;
import org.elasticsearch.common.inject.AbstractModule;

public class AuthModule extends AbstractModule {

    @Override
    protected void configure() {
        bind(AuthService.class).asEagerSingleton();
    }
}