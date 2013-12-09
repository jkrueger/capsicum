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
%% included in all copies or substantiaxl portions of the Software.
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
-export([header_value/2]).
-export([match_space/1]).
-export([start/4]).
-export([start_link/4]).

-ifdef(TEST).
-compile(export_all).
-endif.

-include("capsicum.hrl").
-record(state, {protocol_state=request_wait::atom(),
                request::icap_request(),
                istag::binary(),
                encap_offset::number(),
                encap_elements::list(),
                data = <<>>::binary()}).

-define(VERSION, <<"ICAP/1.0">>).
-define(WS, [$ ,$\r, $\n]).
-define(CRLF, <<"\r\n">>).
-define(LS, [$ ,$,]).

%% @private
header_value(Name, Request) ->
    proplists:get_value(Name, Request#icap_request.headers).

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
%% search binary for a group containing any of the characters in the list
match_group_any_remaining(List, <<C, Rest/binary>> = Remaining, Value) ->
    case etbx:index_of(C, List) of
        undefined -> {ok, Value, Remaining};
        _         -> match_group_any_remaining(List, Rest, Value)
    end;
match_group_any_remaining(_, <<>>, Value) ->
    {ok, Value, <<>>}.

match_group_any(List, <<C, Rest/binary>>, Acc) ->
    case etbx:index_of(C, List) of
        undefined -> match_group_any(List, Rest, <<Acc/binary, C>>);
        _         -> match_group_any_remaining(List, Rest, Acc)
    end;
match_group_any(_, <<>>, Acc) ->
    {not_found, Acc}.
    
%% @private
match_group_any(List, Data) ->
    match_group_any(List, Data, <<>>).

%% @private
read(Incoming, State) ->
    PrevData = State#state.data,
    Data     = <<Incoming/binary, PrevData/binary>>,
    read_line(Data, State).

%% @private
read_request(Type, Parameters, State) ->
    case match_space(Parameters) of
        {ok, URI, Remaining} ->
            case match_any(?WS, Remaining) of
                {ok, ?VERSION, _} -> ok;
                {ok, V, _}        -> throw({bad_version, V});
                {not_found, _}    -> throw({bad_request, Remaining})
            end,
            IcapRequest = #icap_request{uri=URI, type=Type},
            State#state{request        = IcapRequest,
                        protocol_state = headers_wait,
                        data           = <<>>};
        {not_found, _} ->
            throw({bad_request, Parameters})
    end.

%% @private
read(request_wait, Request, State) ->
    {Type, Parameters} =  case Request of 
                              <<"OPTIONS ", Rest/binary>> -> {options,  Rest};
                              <<"REQMOD ",  Rest/binary>> -> {reqmod,   Rest};
                              <<"RESPMOD ", Rest/binary>> -> {respmod,  Rest};
                              _ -> throw({bad_request, Request})
                          end,
    read_request(Type, Parameters, State);
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
            Request = State#state.request,
            Headers  = [ {Name, Value} | Request#icap_request.headers ],
            State#state{request = Request#icap_request{headers=Headers},
                        data    = <<>>};
        {not_found, Line} ->
            throw({bad_request, Line})
    end;
read(prepare_body, Line, State) ->
    Encap  = header_value(<<"Encapsulated">>, State#state.request),
    Elements = parse_encap(Encap),
    [{ProtocolState, _} | _] = Elements,
    NewState = State#state {encap_offset   = 0,
                            encap_elements = Elements,
                            protocol_state = ProtocolState},
    read(ProtocolState, Line, NewState);
read(null_body, Line, State) ->
    read_encap_element(State#state.encap_elements, Line, State);
read(body_wait, Line, State) ->
    read_encap_element(State#state.encap_elements, Line, State);
read(reqhdr_wait, Line, State) ->
    read_encap_element(State#state.encap_elements, Line, State);
read(resphdr_wait, Line, State) ->
    read_encap_element(State#state.encap_elements, Line, State);
read(request_complete, Line, State) ->
    %% WTF?
    io:format("Unexpected data by request complete: ~s~nSTATE: ~p", 
              [Line, State]),
    State.

%% @private
read_encap_element([{ProtocolState, Offset} | Remaining], Line, State) ->
    Buffered  = State#state.data,
    Data      = <<Buffered/binary, Line/binary>>,
    Available = byte_size(Data),
    Offset    = State#state.encap_offset,
    {NextProtocolState, NextOffset, Rest} =
        case Remaining of
            [{NextP, NextO} | R] ->
                {NextP, NextO, R};
            [] ->
                {request_complete, 0, []}
        end,
    Needs = NextOffset-Offset,
    if Available < Needs ->
            State#state{data=Data}; % Buffer data 
       true ->
            NewState0 = set_encap_data(ProtocolState, Needs, Data, State),
            NewState  = NewState0#state{protocol_state = NextProtocolState,
                                        encap_offset   = NextOffset,
                                        encap_elements = Rest},
            read_encap_element(Rest, <<>>, NewState)
    end;
read_encap_element([], Line, State) ->
    Buffered = State#state.data,
    State#state{data           = <<Buffered/binary, Line/binary>>,
                protocol_state = request_complete}.


%% @private
%% TODO: set request dynamically to avoid copy and paste ...
set_encap_data(reqhdr_wait, Length, Data, State) ->
    <<EncapData:Length/binary, Rest/binary>> = Data,
    Request = State#state.request,
    State#state{data=Rest,
                request=Request#icap_request{encap_reqhdr = EncapData}};
set_encap_data(resphdr_wait, Length, Data, State) ->
    <<EncapData:Length/binary, Rest/binary>> = Data,
    Request = State#state.request,
    State#state{data=Rest,
                request=Request#icap_request{encap_resphdr = EncapData}};
set_encap_data(body_wait, Length, Data, State) ->
    <<EncapData:Length/binary, Rest/binary>> = Data,
    Request = State#state.request,
    State#state{data=Rest,
                request=Request#icap_request{encap_body = EncapData}}.
    
%% @private
parse_encap_offset(Data) ->
    case match_group_any(?LS, Data) of
        {ok, Value, Rest} ->
            {list_to_integer(etbx:to_string(Value)), Rest};
        {not_found, V} ->
            {list_to_integer(etbx:to_string(V)), <<>>}
    end.
            
%% @private
parse_encap(<<"req-hdr=", Remaining/binary>>, List) ->
    {ReqHdrO, Rest} = parse_encap_offset(Remaining),
    parse_encap(Rest, [{reqhdr_wait, ReqHdrO} | List]);
parse_encap(<<"res-hdr=", Remaining/binary>>, List) ->
    {RespHdrO, Rest} = parse_encap_offset(Remaining),         
    parse_encap(Rest, [{resphdr_wait, RespHdrO} | List]);
parse_encap(<<"req-body=",Remaining/binary>>, List) ->
    {BodyO, Rest} = parse_encap_offset(Remaining),
    parse_encap(Rest, [{body_wait, BodyO} | List]);
parse_encap(<<"res-body=",Remaining/binary>>, List) ->
    {BodyO, Rest} = parse_encap_offset(Remaining),
    parse_encap(Rest, [{body_wait, BodyO} | List]);
parse_encap(<<"null-body=", Remaining/binary>>, List) ->
    {BodyO, Rest} = parse_encap_offset(Remaining),
    parse_encap(Rest, [{null_body, BodyO} | List]);
parse_encap(<<>>, List) ->
    lists:reverse(List);
parse_encap(Junk, _) ->
    throw({bad_request, Junk}).

parse_encap(Encap) ->
    parse_encap(Encap, []).

%% @private
read_line(Data, State) ->
    case match_eol(Data) of
        {ok, <<$\r>>, <<>>} ->
            State#state{protocol_state = request_complete,
                        data           = <<>>};
        {ok, <<$\r>>, Remaining} ->
            ProtocolState = State#state.protocol_state,
            NewProtocolState =
                if ProtocolState =:= headers_wait -> prepare_body;
                   true -> throw({bad_request, Remaining})
                end,
            read(NewProtocolState, 
                 Remaining,
                 State#state{protocol_state = NewProtocolState,
                             data           = Remaining});
        {ok, Line, Remaining} ->
            NewState = read(State#state.protocol_state, Line, State),
            read_line(Remaining, NewState);
        {not_found, Data} ->
            CurrentData = State#state.data,
            State#state{data = <<CurrentData/binary, Data/binary>>}
    end.

%% @private
decode_uri(<<"icap://", Rest0/binary>>) ->
    case match_char($/, Rest0, <<>>) of
        {ok, Authority, Rest} -> {Authority, [$/ | etbx:to_string(Rest)]};
        {not_found, Rest0}    -> {Rest0, "/"}
    end;
decode_uri(BadURI) -> throw({bad_request, BadURI}).

%% @private
response_status(Status) when is_binary(Status) ->
    Status;
response_status(Code) when is_number(Code) ->
    case Code of
        100 -> <<"100 Continue">>;
        101 -> <<"101 Switching Protocols">>;
        200 -> <<"200 OK">>;
        201 -> <<"201 Created">>;
        202 -> <<"202 Accepted">>;
        203 -> <<"203 Non-Authoritative Information">>;
        204 -> <<"204 No Content">>;
        205 -> <<"205 Reset Content">>;
        206 -> <<"206 Partial Content">>;
        300 -> <<"300 Multiple Choices">>;
        301 -> <<"301 Moved Permanently">>;
        302 -> <<"302 Found">>;
        303 -> <<"303 See Other">>;
        304 -> <<"304 Not Modified">>;
        305 -> <<"305 Use Proxy">>;
        307 -> <<"307 Temporary Redirect">>;
        400 -> <<"400 Bad Request">>;
        401 -> <<"401 Unauthorized">>;
        402 -> <<"402 Payment Required">>;
        403 -> <<"403 Forbidden">>;
        404 -> <<"404 Service Not Found">>;
        405 -> <<"405 Method not Allowed">>;
        406 -> <<"406 Not Acceptable">>;
        407 -> <<"407 Proxy Authentication Required">>;
        408 -> <<"408 Request Timeout">>;
        409 -> <<"409 Conflict">>;
        410 -> <<"410 Gone">>;
        411 -> <<"411 Length Required">>;
        412 -> <<"412 Precondition Failed">>;
        413 -> <<"413 Request Entity Too Large">>;
        414 -> <<"414 Request-URI Too Large">>;
        415 -> <<"415 Unsupported Media Type">>;
        416 -> <<"416 Requested Range Not Satisfiable">>;
        417 -> <<"417 Expectation Failed">>;
        500 -> <<"500 Internal Server error">>;
        501 -> <<"501 Method Not Implemented">>;
        503 -> <<"503 Service Unavailable">>;
        504 -> <<"504 Gateway Time-out">>;
        505 -> <<"505 Version not supported">>
    end;
response_status(Code) ->
    case Code of
	continue	       -> response_status(100);
        ok                     -> response_status(200);
        accepted               -> response_status(202);
        no_content             -> response_status(204);
	moved_permanently      -> response_status(301);
	found                  -> response_status(302);
	see_other	       -> response_status(303);
	not_modified           -> response_status(304);
	use_proxy	       -> response_status(305);
	temporary_redirect     -> response_status(307);
        bad_request            -> response_status(400);
        unauthorized           -> response_status(401);
	forbidden	       -> response_status(403);
        not_found              -> response_status(404);
        method_not_allowed     -> response_status(405);
	not_acceptable         -> response_status(406);
        request_timeout        -> response_status(407);
	unsupported_media_type -> response_status(415);
        server_error           -> response_status(500);
        not_implemented        -> response_status(501);
        service_unavailable    -> response_status(503);
	gateway_timeout        -> response_status(504);
        version_not_supported  -> response_status(505)
    end.

%% @private
respond(Socket, Transport, Type, Opts, State) ->
    {_Authority, Path} = decode_uri(State#state.request#icap_request.uri),
    case proplists:get_value(routes, Opts) of
        undefined -> send_response(not_found, Socket, Transport);
        Routes    -> 
            Route = lists:keyfind(Path, 1, Routes),
            respond(Socket, Transport, Type, Route, Opts, State)
    end.
           
respond(Socket, Transport, _Type, false, _Opts, _State) ->
    send_response(not_found, Socket, Transport);
respond(Socket, Transport, options, {_, _, _, Method}, Opts, State)
  when is_binary(Method) ->
    NumAcceptors = proplists:get_value(acceptors, Opts, 1),
    Acceptors    = etbx:to_binary(etbx:to_string(NumAcceptors)),
    
    Date      = httpd_util:rfc1123_date(),
    Headers   = [{<<"Methods">>, Method},
                 {<<"ISTag">>,   State#state.istag},
                 {<<"Date">>,    etbx:to_binary(Date)},
                 {<<"Max-Connections">>, Acceptors}],
    send_response(ok, Headers, Socket, Transport);
respond(Socket, Transport, _, {_, Module, Handler, _}, Opts, State) ->
    case Module:Handler(State#state.request, Opts) of
        {Code, Response} when is_record(Response, http_response) ->
            {EncapHeader, Body} = encapsulate(Response),
            Headers = [{<<"ISTag">>,   State#state.istag} | 
                       EncapHeader],
            send_response(Code, Headers, Body, Socket, Transport);
        Code -> send_response(Code, Socket, Transport)
    end;
respond(_, _, _, BadRoute, _, _) ->
    throw({server_error, BadRoute}).
 
%% @private
send_response(Code, Socket, Transport) ->
    send_response(Code, [], Socket, Transport).

%% @private
send_response(Code, Headers0, Socket, Transport) ->
    Headers = [{<<"Encapsulated">>, <<"null-body=0">>} | Headers0],
    send_response(Code, Headers, <<>>, Socket, Transport).


send_response(Status, Headers, Body, Socket, Transport) 
  when is_binary(Status) ->
    HeaderLines = encode_headers(?VERSION, Status, Headers),
    Response = [HeaderLines, Body],
    %%%io:format("Response:~n~s~n", [iolist_to_binary(Response)]),
    case Transport:send(Socket, Response) of
        {error, Reason} ->
            io:format("connection closed by client"),
            {error, Reason};
        ok -> ok
    end;
send_response(Code, Headers, Body, Socket, Transport) ->
    send_response(response_status(Code), Headers, Body, Socket, Transport).

%% @private
encode_headers(Version, Status, Headers) ->
    CRLF        = ?CRLF,
    StatusLine  = <<Version/binary, " ", Status/binary, CRLF/binary>>,
    HeaderLines = 
        lists:foldl(
          fun({Name, Value}, Acc) ->
                  <<Acc/binary, Name/binary, ": ", Value/binary, CRLF/binary>>
          end,
          <<StatusLine/binary>>,
          Headers),
    <<HeaderLines/binary, CRLF/binary>>.

%% @private
encapsulate(Response) ->
    Status            = response_status(Response#http_response.code),
    EncapHeaderLines  = encode_headers(<<"HTTP/1.1">>,
                                       Status,
                                       Response#http_response.headers),

    EncapHeaderLen    = byte_size(EncapHeaderLines),
    EncapHeaderLenStr = etbx:to_binary(etbx:to_string(EncapHeaderLen)),
    Body              = Response#http_response.body,
    BodyEncapTag =    case Body of
                          <<>> -> <<"null-body=">>;
                          _    -> <<"res-body=">>
                      end,
    Encapsulation = <<"res-hdr=0, ", 
                      BodyEncapTag/binary, 
                      EncapHeaderLenStr/binary>>,
    {[{<<"Encapsulated">>, Encapsulation}],
     [EncapHeaderLines, Body]}.
    
            
