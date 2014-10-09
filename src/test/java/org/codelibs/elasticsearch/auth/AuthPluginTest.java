package org.codelibs.elasticsearch.auth;

import static org.codelibs.elasticsearch.runner.ElasticsearchClusterRunner.newConfigs;

import java.util.Map;

import junit.framework.TestCase;

import org.codelibs.elasticsearch.runner.ElasticsearchClusterRunner;
import org.codelibs.elasticsearch.runner.net.Curl;
import org.codelibs.elasticsearch.runner.net.CurlResponse;
import org.elasticsearch.common.settings.ImmutableSettings.Builder;
import org.elasticsearch.node.Node;

public class AuthPluginTest extends TestCase {

    private ElasticsearchClusterRunner runner;

    @Override
    protected void setUp() throws Exception {
        // create ES instance
        runner = new ElasticsearchClusterRunner();

        // create ES nodes
        runner.onBuild(new ElasticsearchClusterRunner.Builder() {
            @Override
            public void build(final int number, final Builder settingBuilder) {
            }
        }).build(newConfigs().ramIndexStore().numOfNode(1));

        // wait for yellow status
        runner.ensureYellow();
    }

    @Override
    protected void tearDown() throws Exception {
        // close runner
        runner.close();
        // close all files
        runner.clean();
    }

    public void test_runCluster() throws Exception {

        final String indexAaa = "aaa";
        final String indexBbb = "bbb";
        final String indexCcc = "ccc";
        final String indexDdd = "ddd";

        final String queryUserAdmin = "{\"authenticator\":\"index\",\"username\":\"admin\",\"password\":\"admin123\",\"roles\":[\"admin\"]}";
        final String queryUserTaro = "{\"authenticator\":\"index\",\"username\":\"taro\",\"password\":\"taro123\",\"roles\":[\"user\"]}";
        final String queryUserJiro = "{\"authenticator\":\"index\",\"username\":\"jiro\",\"password\":\"jiro123\",\"roles\":[\"manager\"]}";
        final String queryUserHanako = "{\"authenticator\":\"index\",\"username\":\"hanako\",\"password\":\"hanako123\",\"roles\":[\"manager\",\"admin\"]}";

        final String queryConsAdmin = "{\"paths\":[\"/aaa\",\"/bbb\",\"/ccc\",\"/ddd\"],\"methods\":[\"get\",\"put\",\"post\",\"delete\"],\"roles\":[\"admin\"]}";
        final String queryConsManager = "{\"paths\":[\"/bbb\",\"/ccc\",\"/ddd\"],\"methods\":[\"get\",\"put\",\"post\",\"delete\"],\"roles\":[\"manager\"]}";
        final String queryConsUserCcc = "{\"paths\":[\"/ccc\"],\"methods\":[\"get\"],\"roles\":[\"user\"]}";
        final String queryConsUserDdd = "{\"paths\":[\"/ddd\"],\"methods\":[\"get\",\"put\",\"post\",\"delete\"],\"roles\":[\"user\"]}";
        final String queryConsGuest = "{\"paths\":[\"/ddd\"],\"methods\":[\"get\"],\"roles\":[\"guest\"]}";

        // create index
        runner.createIndex(indexAaa, null);
        runner.createIndex(indexBbb, null);
        runner.createIndex(indexCcc, null);
        runner.createIndex(indexDdd, null);

        if (!runner.indexExists(indexAaa) |
                !runner.indexExists(indexBbb) |
                !runner.indexExists(indexCcc) |
                !runner.indexExists(indexDdd)) {
            fail();
        }

        Node node = runner.node();

        // create users
        /*Curl.delete(node, "/auth/user/_query?q=*:*").execute();*/
        Curl.put(node, "/_auth/account").body(queryUserAdmin).execute();
        Curl.put(node, "/_auth/account").body(queryUserTaro).execute();
        Curl.put(node, "/_auth/account").body(queryUserJiro).execute();
        Curl.put(node, "/_auth/account").body(queryUserHanako).execute();

        // create constraints
        Curl.delete(node, "/security/constraint/_query?q=*:*").execute();
        Curl.post(node, "/security/constraint/admin_all").body(queryConsAdmin).execute();
        Curl.post(node, "/security/constraint/manager_bcd").body(queryConsManager).execute();
        Curl.post(node, "/security/constraint/user_ccc").body(queryConsUserCcc).execute();
        Curl.post(node, "/security/constraint/user_ddd").body(queryConsUserDdd).execute();
        Curl.post(node, "/security/constraint/guest_ddd").body(queryConsGuest).execute();
        Curl.post(node, "/_auth/reload").execute();

        // cleanup
        Curl.delete(node, "/auth/token/_query?q=*:*").execute();

        // Username: taro(user)
        CurlResponse loginTaroResponse = Curl.post(node, "/login")
                .body("{\"username\":\"taro\",\"password\":\"taro123\"}").execute();
        Map<String, Object> loginTaroResponseContentAsMap = loginTaroResponse.getContentAsMap();
        String tokenTaro = loginTaroResponseContentAsMap.get("token").toString();

        try (CurlResponse curlResponse = Curl.get(node, "/aaa/_search")
                .param("q", "*:*").param("token", tokenTaro).execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/bbb/_search")
                .param("q", "*:*").param("token", tokenTaro).execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ccc/_search")
                .param("q", "*:*").param("token", tokenTaro).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ddd/_search")
                .param("q", "*:*").param("token", tokenTaro).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }

        try (CurlResponse curlResponse = Curl.put(node, "/aaa/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.put(node, "/bbb/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ccc/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ddd/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/aaa/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.post(node, "/bbb/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ccc/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ddd/user/1")
                .param("token", tokenTaro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.delete(node, "/aaa/user/1?token=" + tokenTaro).execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/bbb/user/1?token=" + tokenTaro).execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ccc/user/1?token=" + tokenTaro).execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ddd/user/1?token=" + tokenTaro).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/logout?token=" + tokenTaro).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        };

        // Username: jiro(manager)
        CurlResponse loginJiroResponse = Curl.post(node, "/login")
                .body("{\"username\":\"jiro\",\"password\":\"jiro123\"}").execute();
        Map<String, Object> loginJiroResponseContentAsMap = loginJiroResponse.getContentAsMap();
        String tokenJiro = loginJiroResponseContentAsMap.get("token").toString();

        try (CurlResponse curlResponse = Curl.get(node, "/aaa/_search")
                .param("q", "*:*").param("token", tokenJiro).execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/bbb/_search")
                .param("q", "*:*").param("token", tokenJiro).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ccc/_search")
                .param("q", "*:*").param("token", tokenJiro).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ddd/_search")
                .param("q", "*:*").param("token", tokenJiro).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }

        try (CurlResponse curlResponse = Curl.put(node, "/aaa/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.put(node, "/bbb/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ccc/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ddd/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/aaa/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.post(node, "/bbb/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ccc/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ddd/manager/1")
                .param("token", tokenJiro).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.delete(node, "/aaa/manager/1?token=" + tokenJiro).execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/bbb/manager/1?token=" + tokenJiro).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ccc/manager/1?token=" + tokenJiro).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ddd/manager/1?token=" + tokenJiro).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/logout?token=" + tokenJiro).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        };

        // Username: hanako(admin,manager)
        CurlResponse loginHanakoResponse = Curl.post(node, "/login")
                .body("{\"username\":\"hanako\",\"password\":\"hanako123\"}").execute();
        Map<String, Object> loginHanakoResponseContentAsMap = loginHanakoResponse.getContentAsMap();
        String tokenHanako = loginHanakoResponseContentAsMap.get("token").toString();

        try (CurlResponse curlResponse = Curl.get(node, "/aaa/_search")
                .param("q", "*:*").param("token", tokenHanako).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/bbb/_search")
                .param("q", "*:*").param("token", tokenHanako).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ccc/_search")
                .param("q", "*:*").param("token", tokenHanako).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ddd/_search")
                .param("q", "*:*").param("token", tokenHanako).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }

        try (CurlResponse curlResponse = Curl.put(node, "/aaa/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/bbb/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ccc/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ddd/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/aaa/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/bbb/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ccc/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ddd/admin/1")
                .param("token", tokenHanako).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.delete(node, "/aaa/admin/1?token=" + tokenHanako).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/bbb/admin/1?token=" + tokenHanako).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ccc/admin/1?token=" + tokenHanako).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ddd/admin/1?token=" + tokenHanako).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/logout?token=" + tokenHanako).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }

        // Username: admin
        CurlResponse loginAdminResponse = Curl.post(node, "/login")
                .body("{\"username\":\"admin\",\"password\":\"admin123\"}").execute();
        Map<String, Object> loginAdminResponseContentAsMap = loginAdminResponse.getContentAsMap();
        String tokenAdmin = loginAdminResponseContentAsMap.get("token").toString();

        try (CurlResponse curlResponse = Curl.get(node, "/aaa/_search")
                .param("q", "*:*").param("token", tokenAdmin).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/bbb/_search")
                .param("q", "*:*").param("token", tokenAdmin).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ccc/_search")
                .param("q", "*:*").param("token", tokenAdmin).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ddd/_search")
                .param("q", "*:*").param("token", tokenAdmin).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }

        try (CurlResponse curlResponse = Curl.put(node, "/aaa/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/bbb/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ccc/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ddd/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test1\"}").execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/aaa/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/bbb/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ccc/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ddd/admin/1")
                .param("token", tokenAdmin).body("{\"message\":\"test2\"}").execute()) {
            assertEquals(false, curlResponse.getContentAsMap().get("created"));
        }

        try (CurlResponse curlResponse = Curl.delete(node, "/aaa/admin/1?token=" + tokenAdmin).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/bbb/admin/1?token=" + tokenAdmin).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ccc/admin/1?token=" + tokenAdmin).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ddd/admin/1?token=" + tokenAdmin).execute()) {
            assertEquals(true, curlResponse.getContentAsMap().get("found"));
        }

        try (CurlResponse curlResponse = Curl.post(node, "/logout?token=" + tokenAdmin).execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }

        // Username: guest
        try (CurlResponse curlResponse = Curl.get(node, "/aaa/_search").param("q", "*:*").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/bbb/_search").param("q", "*:*").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ccc/_search").param("q", "*:*").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.get(node, "/ddd/_search").param("q", "*:*").execute()) {
            assertEquals(200, curlResponse.getHttpStatusCode());
        }

        try (CurlResponse curlResponse = Curl.put(node, "/aaa/guest/1").body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.put(node, "/bbb/guest/1").body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ccc/guest/1").body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.put(node, "/ddd/guest/1").body("{\"message\":\"test1\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }

        try (CurlResponse curlResponse = Curl.post(node, "/aaa/guest/1").body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.post(node, "/bbb/guest/1").body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ccc/guest/1").body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.post(node, "/ddd/guest/1").body("{\"message\":\"test2\"}").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }

        try (CurlResponse curlResponse = Curl.delete(node, "/aaa/guest/1").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/bbb/guest/1").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ccc/guest/1").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
        try (CurlResponse curlResponse = Curl.delete(node, "/ddd/guest/1").execute()) {
            assertEquals(403, curlResponse.getHttpStatusCode());
        }
    }
}
