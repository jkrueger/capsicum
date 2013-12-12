-module(capsicum_app).
-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

%% @doc Standard OTP application start callback
start(_Type, _Args) ->
    capsicum_sup:start_link().

%% @doc Standard OTP applicatoin stop callback
stop(_State) ->
    ok.
