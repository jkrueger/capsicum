capsicum
========

Erlang ICAP Server

An Erlang implementation (in progress) of an ICAP server as described in [RFC 3507](http://tools.ietf.org/html/rfc3507#ref-4).

## Building

    $ rebar get-deps compile
    
## Unit Tests

    $ rebar eunit (skip_deps=true unless you want to UT dependencies)
    
## Documentation
    $ rebar doc (skip_deps=true unless you want to build documentation for dependencies)
    
## Usage
### Starting an ICAP server
    capsicum:start_icap(Name, Acceptors, RanchOpts, Opts) -> {ok, pid()} | {error, any()}.
    
Where:
* Name is an atom which names the server
* Acceptors indicates how many concurrent listeners should be created
* RanchOpts correspond to options passed to [Ranch](https://github.com/extend/ranch)
* Opts specify the ICAP server options so:
