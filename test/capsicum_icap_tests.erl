-module(capsicum_icap_tests).
-include_lib("eunit/include/eunit.hrl").
-import(capsicum_icap, 
        [match_eol/1, 
         match_any/2,
         match_group_any/2,
         match_space/1, 
         parse_encap/1]).

match_eol_test_() ->
    [?_assertMatch({ok, <<"foo">>, <<"bar">>}, match_eol(<<"foo\nbar">>)),
     ?_assertMatch({not_found, <<"foobar">>},  match_eol(<<"foobar">>)),
     ?_assertMatch({ok, <<>>, <<"foo\nbar">>}, match_eol(<<"\nfoo\nbar">>)),
     ?_assertMatch({ok, <<"foo">>, <<>>},      match_eol(<<"foo\n">>)),
     ?_assertMatch({not_found, <<"foo">>},     match_eol(<<"foo">>)),
     ?_assertMatch({not_found, <<>>},          match_eol(<<>>)),
     ?_assertMatch({ok, <<>>, <<>>},           match_eol(<<$\n>>))].

match_space_test_() ->
    [?_assertMatch({ok, <<"foo">>, <<"bar">>}, match_space(<<"foo bar">>))].

match_any_test_()->
    [?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   match_any([$ ,$., $,], <<"foo.bar">>)),
     ?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   match_any([$ ,$., $,], <<"foo,bar">>)),
     ?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   match_any([$ ,$., $,], <<"foo bar">>)),
     ?_assertMatch({not_found, <<"foo bar">>},
                   match_any([$., $,], <<"foo bar">>))].

match_group_any_test_() ->
    [?_assertMatch({not_found, <<"foobar">>},
                   match_group_any([$,,$.], <<"foobar">>)),
     ?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   match_group_any([$,,$.], <<"foo.bar">>)),
     ?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   match_group_any([$,,$.], <<"foo..bar">>)),
     ?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   match_group_any([$,,$.], <<"foo.,.bar">>)),
     ?_assertMatch({ok, <<"foo">>, <<>>},
                   match_group_any([$,,$.], <<"foo,.,">>))].
    
parse_encap_test_() ->
    [?_assertMatch([{null_body, 42}],
                   parse_encap(<<"null-body=42">>)),
     ?_assertMatch([{reqhdr_wait, 52}],
                   parse_encap(<<"req-hdr=52">>)),
     ?_assertMatch([{reqhdr_wait, 52}, {null_body, 69}], 
                   parse_encap(<<"req-hdr=52, null-body=69">>)),
     ?_assertMatch([{reqhdr_wait, 49}, {resphdr_wait, 52}], 
                   parse_encap(<<"req-hdr=49, res-hdr=52">>)),
     ?_assertMatch([{reqhdr_wait, 49}, {resphdr_wait, 52}, {body_wait, 73}],
                   parse_encap(
                     <<"req-hdr=49, res-hdr=52, req-body=73">>)),
     ?_assertThrow({bad_request, _}, 
                   parse_encap(
                     <<"req-hdr=49, res-hdr=52, req-body=73, resp-body=88">>)),
     ?_assertMatch([{body_wait, 52}], parse_encap(<<"req-body=52">>)),
     ?_assertMatch([{body_wait, 52}], parse_encap(<<"res-body=52">>))].
