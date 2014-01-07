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
%% @doc ICAP Protocol server implementation
-module(capsicum_icap).
-export([header_value/2]).
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
                errored=false::boolean(),
                data   = <<>>::binary(),
                logged = <<>>::binary()}).

-define(VERSION, <<"ICAP/1.0">>).
-define(WS, [$ ,$\r, $\n]).
-define(CRLF, <<"\r\n">>).
-define(LS, [$ ,$,]).

%% @doc Utility function to extract a particular header value from an ICAP
%% request
-spec(header_value(binary(), icap_request()) -> binary() | undefined).
header_value(Name, Request) ->
    proplists:get_value(Name, Request#icap_request.headers).

%% @private
%% @doc Called by Ranch to spawn off a process to handle this protocol. 
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
    try
        loop(Socket, Transport, Timeout, Opts, #state{istag=ISTag})
    catch
        {Type, Description} ->
            Trace  = erlang:get_stacktrace(),
            EError = {error, {Type, Description, Trace}},
            debug("~p error: ~p ~n ~p", [Type, Description, Trace]),
            send_response(Type, Socket, Transport),
            throw(EError);
        _Exception:Reason ->
            EError= {error, Reason, erlang:get_stacktrace()},
            send_response(server_error, Socket, Transport),
            throw(EError)
    end.

-ifdef(DEBUG).
maybe_log(Data, State) ->
    Logged  = State#state.logged,
    NLogged = <<Logged/binary, Data/binary>>,
    State#state{logged=NLogged}.

debug(Format, Args) ->
    lager:info(Format, Args).
debug(Format) ->
    lager:info(Format).
-else.

%% @private
maybe_log(_, State) -> State.
%% @private
debug(_, _) -> undefined.
%% @private
debug(_)    -> undefined.

-endif.

%% @private
loop(Socket, Transport, Timeout, Opts, State0) ->
    case Transport:recv(Socket, 0, Timeout) of
        {ok, Incoming} ->
            State = maybe_log(Incoming, State0),
            NewState = read(State#state.protocol_state, Incoming, State),
            
            if NewState#state.errored or 
               (NewState#state.protocol_state =/= request_complete) ->
                    loop(Socket, Transport, Timeout, Opts, NewState);
               true ->
                    RequestType = NewState#state.request#icap_request.type,
                    case respond(Socket, 
                                 Transport, 
                                 RequestType,
                                 Opts, 
                                 NewState) of 
                        {ok, continue} ->
                            loop(Socket, Transport, Timeout, Opts, NewState);
                        true -> 
                            ok
                    end
            end;        
        Error ->
            if State0#state.errored ->
                    debug("Timing out errored connection: ~n~s~n~p~n",
                          [State0#state.logged,
                           State0#state{logged = <<"SNIP">>}]);
                   true ->
                    ok = Transport:close(Socket),
                    throw(Error)
            end
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
read_request(Type, Parameters, State) ->
    case match_space(Parameters) of
        {ok, URI, Remaining} ->
            case match_any(?WS, Remaining) of
                {ok, ?VERSION, _} -> ok;
                {ok, V, _}        -> throw({bad_version, V});
                {not_found, _}    -> throw({bad_request, Remaining})
            end,
            IcapRequest = #icap_request{uri=URI, type=Type},
            debug("~p [~s]\n", [Type, URI]),
            State#state{request        = IcapRequest,
                        protocol_state = headers_wait};
        {not_found, _} ->
            throw({bad_request, Parameters})
    end.

%% @private
read(request_wait, Incoming, State0) ->
    debug("\n-> request_wait..."),
    case read_line(Incoming, State0) of
        State when is_record(State, state) -> 
            debug("buffering...~n"),
            State;
        {State, Line} ->
            {Type, Parameters} =  
                case Line of 
                    <<"OPTIONS ", Rest/binary>> -> {options,  Rest};
                    <<"REQMOD ",  Rest/binary>> -> {reqmod,   Rest};
                    <<"RESPMOD ", Rest/binary>> -> {respmod,  Rest};
                    _ -> throw({bad_request, Line})
                end,
            NewState = read_request(Type, Parameters, State),
            read(NewState#state.protocol_state, <<>>, NewState)
    end;
read(headers_wait, Incoming, State0) ->
    debug("-> headers_wait..."),
    case read_line(Incoming, State0) of
        State when is_record(State, state) ->
            debug("buffering...~n"),
            State;
        {State, <<"\r">>} ->
            %% Done reading in headers..
            read(prepare_body, <<>>, State);
        {State, Line} ->
            case match_space(Line) of 
                {ok, Name0, Rest} ->
                    %% get rid of the trailing semicolon 
                    %% (which *has* to be there)
                    NLast = binary:last(Name0),
                    Name  =
                        if NLast =/= $: ->
                                throw({bad_request, Name0});
                           true ->
                                binary:part(Name0, {0, byte_size(Name0) - 1})
                        end,
                    VLast = binary:last(Rest),
                    Value = 
                        if  VLast =:= $\r ->
                                binary:part(Rest, {0, byte_size(Rest) - 1});
                            true -> VLast
                        end,
                    Request = State#state.request,
                    Headers  = [ {Name, Value} | Request#icap_request.headers ],
                    debug("~s...", [Name]),
                    NewState =
                        State#state{
                          request = Request#icap_request{headers=Headers},
                          protocol_state = headers_wait},
                    read(headers_wait, <<>>, NewState);
                {not_found, Line} ->
                    throw({bad_request, Line})
            end
    end;
read(prepare_body, Incoming, State) ->
    Encap  = header_value(<<"Encapsulated">>, State#state.request),
    if Encap =/= undefined ->
            debug("-> prepare body ~s~n", [Encap]),
            Elements = parse_encap(Encap),
            [{ProtocolState, _} | _] = Elements,
            NewState = State#state {encap_offset   = 0,
                                    encap_elements = Elements,
                                    protocol_state = ProtocolState},
            read(ProtocolState, Incoming, NewState);
       true -> 
            NewState = State#state{protocol_state=request_complete},
            read(request_complete, Incoming, NewState)
    end;
read(body_wait, Incoming, State0) ->
    debug("-> body_wait..."),
    {Needs, State1} =
        case State0#state.encap_elements of
            V when is_number(V) -> 
                Buffered = State0#state.data,
                Data     = <<Buffered/binary, Incoming/binary>>,
                {V, State0#state{data=Data}};
            _ -> 
                %% chunk starts
                case read_line(Incoming, State0) of
                    {NState, Line} ->
                        debug("~p chunk starts...", [Line]),
                        SizeLength = byte_size(Line)-1, % chop off trailing \r
                        ChunkSize = 
                            try 
                                <<Line:SizeLength/binary>>
                            catch
                                S   -> S;
                                _:_ -> 
                                    debug("bad chunk starts ~p~nData:~p~n",
                                          [Incoming, NState#state.logged]),
                                    throw({bad_request, Line})
                            end,
                        %% + 2 to account for last CRLF which is not strictly
                        %% part of the chunk, unless it is a zero chunk in which
                        %% case.. well.. there is no CRLF of course.
                        V = case binary_to_integer(ChunkSize, 16) of
                                0 -> 0;
                                X -> X+2
                            end,
                        {V, NState#state{encap_elements=V}};
                    NState ->
                        {9999999999, NState}
                end
        end,
    CurrentData = State1#state.data,
    Available = byte_size(CurrentData),
    if Needs == 0 ->
            %% done :)
            debug("end of body~n"),
            Request   = State1#state.request,
            EncapBody = lists:reverse(Request#icap_request.encap_body),
            State1#state{protocol_state=request_complete,
                         request=Request#icap_request{encap_body=EncapBody}};
       Needs > Available ->
            %% try again later..
            debug("~b available (needs ~b)~n",
                  [Available, Needs]),
            State1;
       true ->
            debug("take ~b from available ~b~n", [Needs, Available]),
            %% as pointed above, need to account for extra CRLF at the end
            %% of the chunk .. so - 2 here...
            ActualNeeds = Needs - 2,
            <<Chunk:ActualNeeds/binary, _CR , _LF, ToBuffer/binary>> = 
                CurrentData,
            Request   = State1#state.request,
            EncapBody = Request#icap_request.encap_body,

            NewEncapBody = [{ActualNeeds, Chunk} | EncapBody],
            NewRequest   = Request#icap_request{encap_body=NewEncapBody},
            NewState = State1#state{data=ToBuffer,
                                    encap_elements=[],
                                    request=NewRequest},
            read(body_wait, <<>>, NewState)
    end;
read(reqhdr_wait, Data, State) ->
    debug("-> reqhdr_wait..."),
    read_encap_element(State#state.encap_elements, Data, State);
read(resphdr_wait, Data, State) ->
    debug("resphdr_wait->..."),
    read_encap_element(State#state.encap_elements, Data, State);
read(request_complete, Data, State) ->
    debug("request_complete"),
    RemainingBytes = byte_size(Data),
    if RemainingBytes =/= 0 ->
            debug(" (still remaining: ~b bytes: ~s)\n", [RemainingBytes, Data]);
       true -> 
            debug(".\n")
    end,
    State.

%% @private
read_encap_element([{ProtocolState, Offset} | Remaining], Incoming, State) ->
    Buffered  = State#state.data,
    Data      = <<Buffered/binary, Incoming/binary>>,
    Available = byte_size(Data),
    Offset    = State#state.encap_offset,

    [{NextProtocolState, NextOffset} | _] = Remaining,

    Needs = NextOffset-Offset,

    if Available < Needs ->
            debug("~b available (needs ~b (offset ~b)~n", 
                  [Available, Needs, Offset]),
            State#state{data=Data}; % Buffer data
       true ->
            debug("take ~b from available ~b offset=~b next=~b~n", 
                  [Needs, Available, Offset, NextOffset]),
            <<EncapData:Needs/binary, ToBuffer/binary>> = Data,
            NewState0 = set_encap_data(ProtocolState, Needs, EncapData, State),
            NewState  = NewState0#state{data=ToBuffer,
                                        protocol_state = NextProtocolState,
                                        encap_offset   = NextOffset,
                                        encap_elements = Remaining},
            read(NextProtocolState, <<>>, NewState)
    end;
read_encap_element([], Incoming, State) ->
    Buffered = State#state.data,
    debug("done reading encap elements (left ~b bytes behind)~n",
         [byte_size(State#state.data) + byte_size(Incoming)]),
    State#state{data           = <<Buffered/binary, Incoming/binary>>,
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
                request=Request#icap_request{encap_resphdr = EncapData}}.
    
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
    parse_encap(Rest, [{request_complete, BodyO} | List]);
parse_encap(<<>>, List) ->
    lists:reverse(List);
parse_encap(Junk, _) ->
    throw({bad_request, Junk}).

parse_encap(Encap) ->
    parse_encap(Encap, []).

%% @private
read_line(Incoming, State) ->
    PrevData = State#state.data,
    Data     = <<Incoming/binary, PrevData/binary>>,
    case match_eol(Data) of
        {ok, Line, Remaining} ->
            {State#state{data=Remaining}, Line};
        {not_found, Data} ->
            State#state{data = Data}
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
    Headers0  = [{<<"Methods">>, Method},
                 {<<"ISTag">>,   State#state.istag},
                 {<<"Date">>,    etbx:to_binary(Date)},
                 {<<"Max-Connections">>, Acceptors}],
    Preview   = proplists:get_value(preview, Opts),
    Headers   = if Preview =:= undefined ->
                        Headers0;
                   true ->
                        {<<"Preview">>, Preview}
                end,
    send_response(ok, Headers, Socket, Transport);
respond(Socket, Transport, _, {_, Module, Handler, _}, Opts, State) ->
    case Module:Handler(State#state.request, Opts) of
        {Code, IcapHeaders} ->
            send_response(Code, IcapHeaders, Socket, Transport);
        {Code, IcapHeaders, Response} ->
            {EncapHeader, Body} = encapsulate(Response),
            Headers = [{<<"ISTag">>,   State#state.istag} |
                       [EncapHeader | IcapHeaders]],
            send_response(Code, Headers, Body, Socket, Transport);
        Code when is_atom(Code)   -> 
            send_response(Code, Socket, Transport);
        Code when is_number(Code) ->
            send_response(Code, Socket, Transport)
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

send_response(Code, Headers, Body, Socket, Transport) ->
    send_response(Code, response_status(Code), Headers, Body, Socket, Transport).

send_response(Code, Status, Headers, Body, Socket, Transport) 
  when is_binary(Status) ->
    HeaderLines = encode_headers(?VERSION, Status, Headers),
    Response = [HeaderLines, Body],
    debug("Response:~n~p~n", [Response]),
    case Transport:send(Socket, Response) of
        {error, Reason} ->
            debug("connection closed by client"),
            {error, Reason};
        ok ->
            {ok, Code}
    end.

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
encapsulate(Response) when is_record(Response, http_response) ->
    Status            = response_status(Response#http_response.code),
    Header            = encode_headers(<<"HTTP/1.1">>,
                                       Status,
                                       Response#http_response.headers),
    Body              = chunks_to_iolist(Response#http_response.body),
    encapsulate(<<"res-hdr=0, ">>, 
                <<"null-body=">>,
                <<"res-body=">>, 
                Header,
                Body);
encapsulate(Response) when is_record(Response, http_premade_request) ->
    Header            = Response#http_premade_request.header,
    Body              = chunks_to_iolist(Response#http_premade_request.body),
    encapsulate(<<"req-hdr=0, ">>, 
                <<"null-body=">>,
                <<"req-body=">>, 
                Header, 
                Body);
encapsulate(Response) when is_record(Response, http_premade_response) ->
    Header            = Response#http_premade_response.header,
    Body              = chunks_to_iolist(Response#http_premade_response.body),
    encapsulate(<<"res-hdr=0, ">>, 
                <<"null-body=">>,
                <<"res-body=">>, 
                Header,
                Body).

%% @private
encapsulate(HeaderTag, NullBodyTag, BodyTag, Header, undefined) ->
    encapsulate(HeaderTag, NullBodyTag, BodyTag, Header, <<>>);
encapsulate(HeaderTag, NullBodyTag, BodyTag, Header, Body) ->
    EncapHeaderLen    = byte_size(Header),
    EncapHeaderLenStr = etbx:to_binary(etbx:to_string(EncapHeaderLen)),
    BodyEncapTag      = case Body of
                            <<>> -> NullBodyTag;
                            _    -> BodyTag
                        end,
    Encapsulation = <<HeaderTag/binary,
                      BodyEncapTag/binary, 
                      EncapHeaderLenStr/binary>>,
    {{<<"Encapsulated">>, Encapsulation},
     [Header, Body]}.

%% @private
chunks_to_iolist(Chunks) when is_list(Chunks)->
    lists:foldr(
      fun({Length, Chunk}, Acc) ->
              [integer_to_binary(Length, 16), ?CRLF, Chunk, ?CRLF | Acc]
      end,
      [<<"0">>, ?CRLF, ?CRLF],
      Chunks);
chunks_to_iolist(Chunks) when is_binary(Chunks) ->
    Length = byte_size(Chunks),
    [integer_to_binary(Length, 16), ?CRLF, Chunks, ?CRLF, <<"0">>, ?CRLF, ?CRLF].
