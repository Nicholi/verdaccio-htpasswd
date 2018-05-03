<!--
[![CircleCI](https://circleci.com/gh/verdaccio/verdaccio-htpasswd.svg?style=svg)](https://circleci.com/gh/ayusharma/verdaccio-htpasswd) [![codecov](https://codecov.io/gh/ayusharma/verdaccio-htpasswd/branch/master/graph/badge.svg)](https://codecov.io/gh/ayusharma/verdaccio-htpasswd)
-->

# Verdaccio Module For User Auth Via Htpasswd and Htgroup

`verdaccio-htpasswdhtgroup` is a default authentication plugin for the [Verdaccio](https://github.com/verdaccio/verdaccio).

<!--
## Install

As simple as running:

    $ npm install -g verdaccio-htpasswdhtgroup
-->

## Configure

    auth:
        htpasswdhtgroup:
            file: ./htpasswd
            group_file: ./htgroup
            # Maximum amount of users allowed to register, defaults to "+infinity".
            # You can set this to -1 to disable registration.
            #max_users: 1000

## Logging In

To log in using NPM, run:

```
    npm adduser --registry  https://your.registry.local
```

## Generate htpasswd username/password combination

If you wish to handle access control using htpasswd file, you can generate 
username/password combination form 
[here](http://www.htaccesstools.com/htpasswd-generator/) and add it to htpasswd
file.

## Generate htgroup group/users lists

Each line of the group file contains a groupname followed by a colon, followed by the member usernames separated by spaces.

Example:
> mygroup: bob joe anne

## How does it work?

The htpasswd file contains rows corresponding to a pair of username and password
separated with a colon character. The password is encrypted using the UNIX system's
crypt method and may use MD5 or SHA1.

## Plugin Development in Verdaccio

There are many ways to extend [Verdaccio](https://github.com/verdaccio/verdaccio),
currently it support authentication plugins, middleware plugins (since v2.7.0) 
and storage plugins since (v3.x). 
#### Useful Links
- [Plugin Development](http://www.verdaccio.org/docs/en/dev-plugins.html)
- [List of Plugins](http://www.verdaccio.org/docs/en/plugins.html)
