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

-record(icap_request, {uri              ::binary(),
                       type    = unknown::atom(),
                       headers = []     ::[tuple()],
                       encap_reqhdr     ::binary(),
                       encap_resphdr    ::binary(),
                       encap_body = []  ::list()
                      }).
    
-type icap_request()::#icap_request{}.

-record(http_response, {code          ::atom()|number(),
                        headers = []  ::[tuple()],
                        body    = <<>>::binary()}).

-type http_response()::#http_response{}.

-record(http_premade_request, {header::binary(),
                               body::binary()}).

-record(http_premade_response, {header::binary(),
                                body::binary()}).

-type http_premade_request()::#http_premade_request{}.
