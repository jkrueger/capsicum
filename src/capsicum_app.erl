-module(capsicum_app).
-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_Type, _Args) ->
    capsicum_sup:start_link().

stop(_State) ->
    ok.
