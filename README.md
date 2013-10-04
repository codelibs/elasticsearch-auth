Elasticsearch Auth Plugin
=========================

## Overview

Elasticsearch Auth Plugin provides an authentication filter for Elasticsearch contents.

## User

### Create

    $ curl -XPUT 'localhost:9200/_auth/account' -d "{
        \"authenticator\" : \"index\",
        \"username\" : \"testuser\",
        \"password\" : \"test123\",
        \"roles\" : [\"user\", \"admin\"]
    }"

## Constraint

    $ curl -XPOST 'localhost:9200/security/constraint/' -d "{
        \"authenticator\" : \"index\",
        \"paths\" : [\"/aaa\"],
        \"roles\" : [\"admin\"]
    }"

## Reload Configuration

    $ curl -XPOST 'localhost:9200/_auth/reload'

## Login


    $ curl -XPOST 'localhost:9200/login' -d "{
        \"username\" : \"testuser\",
        \"password\" : \"test123\"
    }"

## Logout


    $ curl -XPOST 'localhost:9200/logout?token=....'



