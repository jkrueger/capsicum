-module(capsicum_icap_tests).
-include_lib("eunit/include/eunit.hrl").

match_eol_test_() ->
    [?_assertMatch({ok, <<"foo">>, <<"bar">>}, 
                   capsicum_icap:match_eol(<<"foo\nbar">>)),
     ?_assertMatch({not_found, <<"foobar">>},
                   capsicum_icap:match_eol(<<"foobar">>)),
     ?_assertMatch({ok, <<>>, <<"foo\nbar">>},
                   capsicum_icap:match_eol(<<"\nfoo\nbar">>)),
     ?_assertMatch({ok, <<"foo">>, <<>>},
                   capsicum_icap:match_eol(<<"foo\n">>)),
     ?_assertMatch({not_found, <<"foo">>},
                   capsicum_icap:match_eol(<<"foo">>)),
     ?_assertMatch({not_found, <<>>},
                   capsicum_icap:match_eol(<<>>)),
     ?_assertMatch({ok, <<>>, <<>>}, 
                   capsicum_icap:match_eol(<<$\n>>))].

match_space_test_() ->
    [?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   capsicum_icap:match_space(<<"foo bar">>))].

match_any_test_()->
    [?_assertMatch({ok, <<"foo">>, <<"bar">>},
                  capsicum_icap:match_any([$ ,$., $,], <<"foo.bar">>)),
     ?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   capsicum_icap:match_any([$ ,$., $,], <<"foo,bar">>)),
     ?_assertMatch({ok, <<"foo">>, <<"bar">>},
                   capsicum_icap:match_any([$ ,$., $,], <<"foo bar">>)),
     ?_assertMatch({not_found, <<"foo bar">>},
                   capsicum_icap:match_any([$., $,], <<"foo bar">>))
    ].
