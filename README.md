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
| master | 0.90.5        |

## Installation

    $ $ES_HOME/bin/plugin -install auth -url https://.../elasticsearch-auth...zip (see below)

ZIP file for Auth plugin is in [HERE](https://oss.sonatype.org/content/repositories/snapshots/org/codelibs/elasticsearch-auth/).

## User Management

The user management feature for Auth plugin is an extensible implementation. 
The default implementation is that Auth plugin stores user info into Elasticsearch index (org.codelibs.elasticsearch.auth.security.Authenticator).
If you want yoru own authentication system, such as LDAP, you can create your Authenticator class.

IndexAuthenticator is a default implementation for managing users.
The authenticator name is index.
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

The published token is managed in your application, and then it needs to be set to a request parameter or a cookie.

### Logout

The published token is discarded by:

    $ curl -XPOST 'localhost:9200/logout?token=....'


### TTL for Token

Using ttl of Elasticsearch, expired token is discarded automatically.

    $ curl -XPUT 'localhost:9200/auth/token/_mapping' -d "{
        \"_ttl\" : { \"enabled\" : true, \"default\" : \"1d\" }
    }"


