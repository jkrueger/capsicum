%%
%% @author Erick Gonzalez <erick@codemonkeylabs.de>
%% @copyright 2013 Erick Gonzalez
%%
%% Permission is hereby granted, free of charge, to any person obtaining
%% a copy of this software and associated documentation files (the
%% "Software"), to deal in the Software without restriction, including
%% without limitation the rights to use, copy, modify, merge, publish,
%% distribute, sublicense, and/or sell copies of the Software, and to
%% permit persons to whom the Software is furnished to do so, subject
%% to the following conditions:
%%
%% The above copyright notice and this permission notice shall be
%% included in all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
%% EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
%% MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
%% IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
%% ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
%% CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
%% WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
%%
%% @doc An Erlang ICAP (Internet Content Adaptation Protocol) Server

-module(capsicum).
-export([start/0]).
-export([start_icap/4]).

%% @doc Starts an ICAP server
%% this is pretty much the main and only function that a given server
%% implementation needs to call. It will start the server with the given
%% Name, number of listeners (i.e. Acceptors), options to pass to Ranch and 
%% finally the options for the icap server. Current options are:
%% {timeout, number()} -> time in milliseconds to wait before giving up on a
%%                        connection
%% {routes, Descriptors} -> list of ICAP routes to map URIs to service modules.
%% 
%% Descriptors = list(Descriptor)
%% Descriptor  = {URI::string(), 
%%                Module::atom(),
%%                Function::atom(),
%%                RequestType::binary()}
%% 
%% 
-spec(start_icap(atom(), number(), [tuple()], [tuple()]) -> 
             {ok, pid()} | {error, any()}).
start_icap(Name, Acceptors, RanchOpts, Opts) ->
    ranch:start_listener(Name, 
                         Acceptors, 
                         ranch_tcp, 
                         RanchOpts,
                         capsicum_icap,
                         Opts).

%% @doc starts Capsicum application and all its dependencies
-spec(start() -> {ok, list()}).
start() ->
    etbx:start_app(capsicum).
