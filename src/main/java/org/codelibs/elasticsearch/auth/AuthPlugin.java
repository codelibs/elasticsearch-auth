package org.codelibs.elasticsearch.auth;

import java.util.Collection;

import org.codelibs.elasticsearch.auth.module.AuthModule;
import org.codelibs.elasticsearch.auth.rest.AccountRestAction;
import org.codelibs.elasticsearch.auth.rest.ReloadRestAction;
import org.codelibs.elasticsearch.auth.service.AuthService;
import org.elasticsearch.common.collect.Lists;
import org.elasticsearch.common.component.LifecycleComponent;
import org.elasticsearch.common.inject.Module;
import org.elasticsearch.plugins.AbstractPlugin;
import org.elasticsearch.rest.RestModule;

public class AuthPlugin extends AbstractPlugin {
    @Override
    public String name() {
        return "AuthPlugin";
    }

    @Override
    public String description() {
        return "This is a elasticsearch-auth plugin.";
    }

    // for Rest API
    public void onModule(final RestModule module) {
        module.addRestAction(AccountRestAction.class);
        module.addRestAction(ReloadRestAction.class);
    }

    // for Service
    @Override
    public Collection<Class<? extends Module>> modules() {
        final Collection<Class<? extends Module>> modules = Lists
                .newArrayList();
        modules.add(AuthModule.class);
        return modules;
    }

    // for Service
    @SuppressWarnings("rawtypes")
    @Override
    public Collection<Class<? extends LifecycleComponent>> services() {
        final Collection<Class<? extends LifecycleComponent>> services = Lists
                .newArrayList();
        services.add(AuthService.class);
        return services;
    }
}
