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
%% @doc ICAP Protocol implementation
-module(capsicum_icap).
-export([start/4]).
-export([start_link/4]).

-ifdef(TEST).
-export([match_eol/1]).
-export([match_space/1]).
-export([match_any/2]).
-endif.

-record(icap_request, {uri::binary(),
                       type=unknown::atom()}).
-type icap_request()::#icap_request{}.
-record(state, {protocol_state=request_wait::atom(),
                request::icap_request(),
                headers=[]::[tuple()],
                istag::binary(),
                data = <<>>::binary()}).

-define(VERSION, <<"ICAP/1.0">>).
-define(WS, [$ ,$\r, $\n]).
-define(CRLF, <<"\r\n">>).

%% @doc Called by ranch to spawn off a process to handle this protocol
start_link(Ref, Socket, Transport, Opts) ->
    Pid = spawn_link(?MODULE, start, [Ref, Socket, Transport, Opts]),
    {ok, Pid}.

%% @private
start(Ref, Socket, Transport, Opts) ->
    ok = ranch:accept_ack(Ref),
    Timeout = proplists:get_value(timeout, Opts, 5000),
    Time    = calendar:universal_time(),
    Seconds = calendar:datetime_to_gregorian_seconds(Time),
    ISTag   = etbx:to_binary(httpd_util:integer_to_hexlist(Seconds)),
    loop(Socket, Transport, Timeout, Opts, #state{istag=ISTag}).

%% @private
loop(Socket, Transport, Timeout, Opts, State) ->
    try
        case Transport:recv(Socket, 0, Timeout) of
            {ok, Incoming} ->
                NewState = read(Incoming, State),
                if NewState#state.protocol_state =:= request_complete ->
                        RequestType = NewState#state.request#icap_request.type,
                        respond(Socket, Transport, RequestType, Opts, NewState);
                   true -> loop(Socket, Transport, Timeout, Opts, NewState)
                end;
            Error ->
                ok = Transport:close(Socket),
                throw(Error)
        end
    catch
        {Type, Description} ->
            io:format("Error: ~p ~s~n~p~n", [Type, 
                                             Description,
                                             erlang:get_stacktrace()]),
            send_response(Type, Socket, Transport);
        _Exception:Reason ->
            io:format("Internal ~p:~p~n", [Reason, 
                                           erlang:get_stacktrace()]),
            send_response(server_error, Socket, Transport)
    end.

%% @private
%% search binary for a single character (for performance)
match_char(Char, <<Char, Rest/binary>>, Acc) ->
    {ok, Acc, Rest};
match_char(Char, <<C, Rest/binary>>, Acc) ->
    match_char(Char, Rest, <<Acc/binary, C>>);
match_char(_, <<>>, Acc) ->
    {not_found, Acc}.

%% @private
match_eol(Data) ->
    match_char($\n, Data, <<>>).
%% @private
match_space(Data) ->
    match_char($ , Data, <<>>).

%% @private
%% search binary for any of the characters in list
match_any(List, <<C, Rest/binary>>, Acc) ->
    case etbx:index_of(C, List) of
        undefined -> match_any(List, Rest, <<Acc/binary, C>>);
        _         -> {ok, Acc, Rest}
    end;
match_any(_, <<>>, Acc) ->
    {not_found, Acc}.

%% @private
match_any(List, Data) ->
    match_any(List, Data, <<>>).

%% @private
read(Incoming, State) ->
    PrevData = State#state.data,
    Data     = <<Incoming/binary, PrevData/binary>>,
    read_line(Data, State).

%% @private
read(request_wait, Request, State) ->
    case Request of 
        <<"OPTIONS ", Parameters/binary>> ->
            case match_space(Parameters) of
                {ok, URI, Remaining} ->
                    case match_any(?WS, Remaining) of
                        {ok, ?VERSION, _} -> ok;
                        {ok, V, _}        -> throw({bad_version, V});
                        {not_found, _}    -> throw({bad_request, Remaining})
                    end,
                    IcapRequest = #icap_request{uri=URI, type=options},
                    State#state{request        = IcapRequest,
                                protocol_state = headers_wait};
                {not_found, _} ->
                    throw({bad_request, Parameters})
            end;
        _ ->
            throw({bad_request, Request})
    end;
read(headers_wait, Line, State) ->
    case match_space(Line) of 
        {ok, Name0, Rest} ->
            %% get rid of the trailing semicolon (which *has* to be there)
            NLast = binary:last(Name0),
            Name  = if NLast =/= $: ->
                            throw({bad_request, Name0});
                       true ->
                            binary:part(Name0, {0, byte_size(Name0) - 1})
                    end,
            VLast = binary:last(Rest),
            Value = if  VLast =:= $\r ->
                            binary:part(Rest, {0, byte_size(Rest) - 1});
                       true -> VLast
                    end,
            Headers  = [ {Name, Value} | State#state.headers ],
            State#state{headers=Headers};
        {not_found, Line} ->
            throw({bad_request, Line})
    end.

%% @private
read_line(Data, State) ->
    case match_eol(Data) of
        {ok, <<$\r>>,    Remaining} ->
            case State#state.request#icap_request.type of
                options -> 
                    if Remaining =/= <<>> -> throw({bad_request, Remaining});
                       true -> State#state{protocol_state = request_complete,
                                           data           = <<>>}
                    end;
                unknown -> read_line(Remaining, State)
            end;
        {ok, Line, Remaining} ->
            NewState = read(State#state.protocol_state, Line, State),
            read_line(Remaining, NewState);
        {not_found, Data} ->
            #state{data=Data}
    end.

%% @private
decode_uri(<<"icap://", Rest0/binary>>) ->
    case match_char($/, Rest0, <<>>) of
        {ok, Authority, Rest} -> {Authority, [$/ | etbx:to_string(Rest)]};
        {not_found, Rest0}    -> {Rest0, "/"}
    end;
decode_uri(BadURI) -> throw({bad_request, BadURI}).

%% @private
response_code(Type) ->
    case Type of
        ok                    -> <<"200 OK">>;
        accepted              -> <<"202 Accepted">>;
        bad_request           -> <<"400 Bad request">>;
        unauthorized          -> <<"401 Unauthorized">>;
        not_found             -> <<"404 ICAP Service not found">>;
        method_not_allowed    -> <<"405 Method not allowed for service">>;
        request_timeout       -> <<"407 Request timeout">>;
        server_error          -> <<"500 Server error">>;
        not_implemented       -> <<"501 Method not implemented">>;
        service_unavailable   -> <<"503 Service overloaded">>;
        version_not_supported -> <<"505 ICAP version not supported">>
    end.

%% @private
respond(Socket, Transport, options, Opts, State) ->
    {_Authority, Path} = decode_uri(State#state.request#icap_request.uri),
    case proplists:get_value(routes, Opts) of
        undefined -> send_response(not_found, Socket, Transport);
        Routes    ->
            case lists:keyfind(Path, 1, Routes) of
                false -> send_response(not_found, Socket, Transport);
                {Path, _, Method} when is_binary(Method) ->
                    NumAcceptors = proplists:get_value(acceptors, Opts, 1),
                    Acceptors    = etbx:to_binary(etbx:to_string(NumAcceptors)),
                    
                    Date      = httpd_util:rfc1123_date(),
                    Headers   = [{<<"Methods">>, Method},
                                 {<<"ISTag">>,   State#state.istag},
                                 {<<"Date">>,    etbx:to_binary(Date)},
                                 {<<"Max-Connections">>, Acceptors}],
                    send_response(ok, Headers, Socket, Transport);
                BadRoute -> throw({server_error, BadRoute})
            end
    end.
            
%% @private
send_response(Code, Socket, Transport) ->
    send_response(Code, [], Socket, Transport).

%% @private
send_response(Code, Headers0, Socket, Transport) ->
    Headers = [{<<"Encapsulated">>, <<"null-body=0">>} | Headers0],
    send_response(Code, Headers, <<>>, Socket, Transport).

send_response(Type, Headers, Body, Socket, Transport) when is_atom (Type) ->
    send_response(response_code(Type), Headers, Body, Socket, Transport);
send_response(Code, Headers, Body, Socket, Transport) when is_binary(Code) ->
    Version     = ?VERSION,
    CRLF        = ?CRLF,
    StatusLine  = <<Version/binary, " ", Code/binary, CRLF/binary>>,
    HeaderLines =
        lists:foldl(
          fun({Name, Value}, Acc) ->
                  <<Acc/binary, Name/binary, ": ", Value/binary, CRLF/binary>>
          end,
          <<>>,
          Headers),
    Response = [StatusLine, HeaderLines, ?CRLF, Body],
    io:format("Response:~n~s~n", [iolist_to_binary(Response)]),
    ok = Transport:send(Socket, Response).
