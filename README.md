Elasticsearch Auth Plugin
=========================

## Overview

Elasticsearch Auth Plugin provides an authentication filter for Elasticsearch contents.
This plugin consists of:

* User Management
* Content Constraints
* Login/Logout

## Version

| Auth   | elasticsearch |
|:------:|:-------------:|
| master | 1.2.x         |
| 1.3.0  | 1.3.1         |
| 1.2.0  | 1.2.1         |
| 1.1.0  | 1.0.0         |
| 1.0.1  | 0.90.11       |

### Issues/Questions

Please file an [issue](https://github.com/codelibs/elasticsearch-auth/issues "issue").
(Japanese forum is [here](https://github.com/codelibs/codelibs-ja-forum "here").)

## Installation

    $ $ES_HOME/bin/plugin --install org.codelibs/elasticsearch-auth/1.3.0

## User Management

The user management feature for Auth plugin is an extensible implementation. 
The default implementation is that Auth plugin stores user info into Elasticsearch index (org.codelibs.elasticsearch.auth.security.Authenticator).
If you want yoru own authentication system, such as LDAP, you can create your Authenticator class.

IndexAuthenticator is a default implementation for managing users.
The authenticator name is 'index'.
The user information contains a password and roles.

### Create User

    $ curl -XPUT 'localhost:9200/_auth/account' -d "{
        \"authenticator\" : \"index\",
        \"username\" : \"testuser\",
        \"password\" : \"test123\",
        \"roles\" : [\"user\", \"admin\"]
    }"

### Update User

    $ curl -XPOST 'localhost:9200/_auth/account' -d "{
        \"authenticator\" : \"index\",
        \"username\" : \"testuser\",
        \"password\" : \"test321\",
        \"roles\" : [\"user\"]
    }"

### Delete User

    $ curl -XDELETE 'localhost:9200/_auth/account' -d "{
        \"authenticator\" : \"index\",
        \"username\" : \"testuser\"
    }"

## Content Constraints

Contents are restricted by a content constraints.
The content constraint consists of paths, HTTP methods and roles.

If you want to allow "admin" users to access to /aaa by GET and POST method, the configuration is below:

    $ curl -XPOST 'localhost:9200/security/constraint/' -d "{
        \"authenticator\" : \"index\",
        \"paths\" : [\"/aaa\"],
        \"methods\" : [\"get\", \"post\"],
        \"roles\" : [\"admin\"]
    }"

"paths" is a prefix matching.

If "user" users access to /bbb by only GET method:

    $ curl -XPOST 'localhost:9200/security/constraint/' -d "{
        \"authenticator\" : \"index\",
        \"paths\" : [\"/bbb\"],
        \"methods\" : [\"get\"],
        \"roles\" : [\"user\"]
    }"

### Reload Configuration

    $ curl -XPOST 'localhost:9200/_auth/reload'

## Login/Logout

User accesses to restricted contents on Elasticsearch by a token published by Auth plugin.

### Login

The token is published by:

    $ curl -XPOST 'localhost:9200/login' -d "{
        \"username\" : \"testuser\",
        \"password\" : \"test123\"
    }"
    
and the response is:

    {
      "status" : 200,
      "token" : "..."
    }

The published token is managed in your application, and then it needs to be set to a request parameter or a cookie.

### Access to Elasticsearch

Requesting with a token, the content will be obtained.

    $ curl -XGET http://localhost:9200/aaa_search?q=\*:\*&token=...

or

    $ curl --cookie "eaid=..." -XGET http://localhost:9200/aaa/_search?q=\*:\*

'eaid' is a token key on a cookie.

### Logout

The published token is discarded by:

    $ curl -XPOST 'localhost:9200/logout?token=....'


### TTL for Token

Using ttl of Elasticsearch, expired token is discarded automatically.

    $ curl -XPUT 'localhost:9200/auth/token/_mapping' -d "{
        \"_ttl\" : { \"enabled\" : true, \"default\" : \"1d\" }
    }"


