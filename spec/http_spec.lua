describe("http patterns", function()
	local http = require "lpeg_patterns.http"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a SLUG header", function()
		local SLUG = http.SLUG * EOF
		assert.same("foo", SLUG:match("foo"))
		assert.same("foo bar", SLUG:match("foo bar"))
		assert.same("foo bar", SLUG:match("foo  bar"))
		assert.same("foo   bar", SLUG:match("foo %20 bar"))
	end)
	it("Parses an Origin header", function()
		local Origin = lpeg.Ct(http.Origin) * EOF
		assert.same({}, Origin:match("null"))
		assert.same({"http://example.com"}, Origin:match("http://example.com"))
		assert.same({"http://example.com", "https://foo.org"}, Origin:match("http://example.com https://foo.org"))
	end)
	it("Parses an X-Frame-Options header", function()
		local X_Frame_Options = lpeg.Ct(http.X_Frame_Options) * EOF
		assert.same({"deny"}, X_Frame_Options:match("deny"))
		assert.same({"deny"}, X_Frame_Options:match("DENY"))
		assert.same({"deny"}, X_Frame_Options:match("dEnY"))
		assert.same({"http://example.com"}, X_Frame_Options:match("Allow-From http://example.com"))
	end)
	it("Splits a request line", function()
		local request_line = lpeg.Ct(http.request_line) * EOF
		assert.same({"GET", "/", 1.0}, request_line:match("GET / HTTP/1.0\r\n"))
		assert.same({"GET", "http://foo.com/", 1.0}, request_line:match("GET http://foo.com/ HTTP/1.0\r\n"))
		assert.same({"OPTIONS", "*", 1.1}, request_line:match("OPTIONS * HTTP/1.1\r\n"))
	end)
	it("Splits an Upgrade header", function()
		local Upgrade = lpeg.Ct(http.Upgrade) * EOF
		assert.same({"Foo"}, Upgrade:match("Foo"))
		assert.same({"WebSocket"}, Upgrade:match("WebSocket"))
		assert.same({"HTTP/2.0", "SHTTP/1.3", "IRC/6.9", "RTA/x11"}, Upgrade:match("HTTP/2.0, SHTTP/1.3, IRC/6.9, RTA/x11"))
	end)
	it("Splits a Via header", function()
		local Via = lpeg.Ct(http.Via) * EOF
		assert.same({{protocol="HTTP/1.0", by="fred"}}, Via:match("1.0 fred"))
		assert.same({{protocol="HTTP/1.0", by="fred"}}, Via:match("HTTP/1.0 fred"))
		assert.same({{protocol="Other/myversion", by="fred"}}, Via:match("Other/myversion fred"))
		assert.same({{protocol="HTTP/1.1", by="p.example.net"}}, Via:match("1.1 p.example.net"))
		assert.same({
			{protocol="HTTP/1.0", by="fred"},
			{protocol="HTTP/1.1", by="p.example.net"}
		}, Via:match("1.0 fred, 1.1 p.example.net"))
		assert.same({
			{protocol="HTTP/1.0", by="my.host:80"},
			{protocol="HTTP/1.1", by="my.other.host"}
		}, Via:match("1.0 my.host:80, 1.1 my.other.host"))
		assert.same({
			{protocol="HTTP/1.0", by="fred"},
			{protocol="HTTP/1.1", by="p.example.net"}
		}, Via:match(",,,1.0 fred ,  ,,, 1.1 p.example.net,,,"))
	end)
	it("Handles folding whitespace in field_value", function()
		local field_value = http.field_value * EOF
		assert.same("Foo", field_value:match("Foo"))
		-- doesn't remove repeated whitespace
		assert.same("Foo  Bar", field_value:match("Foo  Bar"))
		-- unfolds whitespace broken over multiple lines
		assert.same("Foo Bar", field_value:match("Foo\r\n Bar"))
		assert.same("Foo Bar", field_value:match("Foo \r\n Bar"))
	end)
	it("Splits a Connection header", function()
		local Connection = lpeg.Ct(http.Connection) * EOF
		assert.same({}, Connection:match(" "))
		assert.same({}, Connection:match(","))
		assert.same({}, Connection:match(",    ,"))
		assert.same({"foo"}, Connection:match("foo"))
		assert.same({"foo"}, Connection:match(" foo"))
		assert.same({"foo"}, Connection:match(" foo,,,"))
		assert.same({"foo"}, Connection:match(",, , foo  "))
		assert.same({"foo", "bar"}, Connection:match("foo,bar"))
		assert.same({"foo", "bar"}, Connection:match("foo, bar"))
		assert.same({"foo", "bar"}, Connection:match("foo , bar"))
		assert.same({"foo", "bar"}, Connection:match("foo\t, bar"))
		assert.same({"foo", "bar"}, Connection:match("foo,,,  ,bar"))
	end)
	it("Parses a Transfer-Encoding header", function()
		local Transfer_Encoding = lpeg.Ct(http.Transfer_Encoding) * EOF
		assert.falsy(Transfer_Encoding:match("")) -- doesn't allow empty
		assert.same({{"foo"}}, Transfer_Encoding:match("foo"))
		assert.same({{"foo"}, {"bar"}}, Transfer_Encoding:match("foo, bar"))
		assert.same({{"foo", someext = "bar"}}, Transfer_Encoding:match("foo;someext=bar"))
		assert.same({{"foo", someext = "bar", another = "qux"}}, Transfer_Encoding:match("foo;someext=bar;another=\"qux\""))
		-- q not allowed
		assert.falsy(Transfer_Encoding:match("foo;q=0.5"))
		-- check transfer parameters starting with q (but not q) are allowed
		assert.same({{"foo", queen = "foo"}}, Transfer_Encoding:match("foo;queen=foo"))
	end)
	it("Parses a TE header", function()
		local TE = lpeg.Ct(http.TE) * EOF
		assert.same({}, TE:match("")) -- allows empty
		assert.same({{"foo"}}, TE:match("foo"))
		assert.same({{"foo"}, {"bar"}}, TE:match("foo, bar"))
		assert.same({{"foo", q=0.5}}, TE:match("foo;q=0.5"))
		assert.same({{"foo", someext = "foo", q=0.5}}, TE:match("foo;someext=foo;q=0.5"))
	end)
	it("Splits a Trailer header", function()
		local Trailer = lpeg.Ct(http.Trailer) * EOF
		assert.falsy(Trailer:match(" "))
		assert.falsy(Trailer:match(","))
		assert.falsy(Trailer:match(",    ,"))
		assert.same({"foo"}, Trailer:match("foo"))
		assert.same({"foo"}, Trailer:match(" foo"))
		assert.same({"foo"}, Trailer:match(" foo,,,"))
		assert.same({"foo"}, Trailer:match(",, , foo  "))
		assert.same({"foo", "bar"}, Trailer:match("foo,bar"))
		assert.same({"foo", "bar"}, Trailer:match("foo, bar"))
		assert.same({"foo", "bar"}, Trailer:match("foo , bar"))
		assert.same({"foo", "bar"}, Trailer:match("foo\t, bar"))
		assert.same({"foo", "bar"}, Trailer:match("foo,,,  ,bar"))
	end)
	it("Parses a Content-Type header", function()
		local Content_Type = http.Content_Type * EOF
		assert.same({ type = "foo", subtype = "bar", parameters = {}},
			Content_Type:match("foo/bar"))
		assert.same({ type = "foo", subtype = "bar", parameters = {param="value"}},
			Content_Type:match("foo/bar;param=value"))
		-- Examples from RFC7231 3.1.1.1.
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}},
			Content_Type:match([[text/html;charset=utf-8]]))
		-- assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}},
		-- 	Content_Type:match([[text/html;charset=UTF-8]]))
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}},
			Content_Type:match([[Text/HTML;Charset="utf-8"]]))
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}},
			Content_Type:match([[text/html; charset="utf-8"]]))
	end)
	it("Parses an Accept header", function()
		local Accept = lpeg.Ct(http.Accept) * EOF
		assert.same({{type = "foo", subtype = "bar", parameters = {}, q = nil, extensions = {}}}, Accept:match("foo/bar"))
		assert.same({
				{type = "audio", subtype = nil, parameters = {}, q = 0.2, extensions = {}};
				{type = "audio", subtype = "basic", parameters = {}, q = nil, extensions = {}};
			}, Accept:match("audio/*; q=0.2, audio/basic"))
		assert.same({
				{type = "text", subtype = "plain", parameters = {}, q = 0.5, extensions = {}};
				{type = "text", subtype = "html", parameters = {}, q = nil, extensions = {}};
				{type = "text", subtype = "x-dvi", parameters = {}, q = 0.8, extensions = {}};
				{type = "text", subtype = "x-c", parameters = {}, q = nil, extensions = {}};
			}, Accept:match("text/plain; q=0.5, text/html, text/x-dvi; q=0.8, text/x-c"))
		assert.same({
				{type = "text", subtype = nil, parameters = {}, extensions = {}};
				{type = "text", subtype = "plain", parameters = {}, extensions = {}};
				{type = "text", subtype = "plain", parameters = {format = "flowed"}, extensions = {}};
				{type = nil, subtype = nil, parameters = {}, extensions = {}};
			}, Accept:match("text/*, text/plain, text/plain;format=flowed, */*"))
		assert.same({
				{type = "text", subtype = nil, parameters = {}, q = 0.3, extensions = {}};
				{type = "text", subtype = "html", parameters = {}, q = 0.7, extensions = {}};
				{type = "text", subtype = "html", parameters = {level = "1"}, q = nil, extensions = {}};
				{type = "text", subtype = "html", parameters = {level = "2"}, q = 0.4, extensions = {}};
				{type = nil, subtype = nil, parameters = {}, q = 0.5, extensions = {}};
			}, Accept:match("text/*;q=0.3, text/html;q=0.7, text/html;level=1,text/html;level=2;q=0.4, */*;q=0.5"))
	end)
	it("Matches the 3 date formats", function()
		local Date = http.Date * EOF
		local example_time = {
			year = 1994;
			month = 11;
			day = 6;
			hour = 8;
			min = 49;
			sec = 37;
			wday = 1;
		}
		assert.same(example_time, Date:match"Sun, 06 Nov 1994 08:49:37 GMT")
		assert.same(example_time, Date:match"Sunday, 06-Nov-94 08:49:37 GMT")
		assert.same(example_time, Date:match"Sun Nov  6 08:49:37 1994")
	end)
	it("Parses a Sec-WebSocket-Extensions header", function()
		local Sec_WebSocket_Extensions = lpeg.Ct(http.Sec_WebSocket_Extensions) * EOF
		assert.same({{"foo", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo")
		assert.same({{"foo", parameters = {}}, {"bar", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo, bar")
		assert.same({{"foo", parameters = {hello = true; world = "extension"}}, {"bar", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo;hello;world=extension, bar")
		assert.same({{"foo", parameters = {hello = true; world = "extension"}}, {"bar", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo;hello;world=\"extension\", bar")
		-- quoted strings must be valid tokens
		assert.falsy(Sec_WebSocket_Extensions:match"foo;hello;world=\"exte\\\"nsion\", bar")
	end)
	it("Parses a Sec_WebSocket-Version-Client header", function()
		local Sec_WebSocket_Version_Client = http.Sec_WebSocket_Version_Client * EOF
		assert.same(1, Sec_WebSocket_Version_Client:match"1")
		assert.same(100, Sec_WebSocket_Version_Client:match"100")
		assert.same(255, Sec_WebSocket_Version_Client:match"255")
		assert.falsy(Sec_WebSocket_Version_Client:match"0")
		assert.falsy(Sec_WebSocket_Version_Client:match"256")
		assert.falsy(Sec_WebSocket_Version_Client:match"1.2")
		assert.falsy(Sec_WebSocket_Version_Client:match"090")
	end)
	it("Parses a Link header", function()
		local Link = lpeg.Ct(http.Link) * EOF
		assert.same({{{host="example.com"}}}, Link:match"<//example.com>")
		assert.same({
			{
				{scheme = "http"; host = "example.com"; path = "/TheBook/chapter2";};
				rel = "previous";
				title="previous chapter"
			}},
			Link:match[[<http://example.com/TheBook/chapter2>; rel="previous"; title="previous chapter"]])
		assert.same({{{path = "/"}, rel = "http://example.net/foo"}},
			Link:match[[</>; rel="http://example.net/foo"]])
		assert.same({
				{{path = "/TheBook/chapter2"}, rel = "previous", title = "letztes Kapitel"};
				{{path = "/TheBook/chapter4"}, rel = "next", title = "nächstes Kapitel"};
			},
			Link:match[[</TheBook/chapter2>; rel="previous"; title*=UTF-8'de'letztes%20Kapitel, </TheBook/chapter4>; rel="next"; title*=UTF-8'de'n%c3%a4chstes%20Kapitel]])
		assert.same({{{scheme = "http"; host = "example.org"; path = "/"}, rel = "start http://example.net/relation/other"}},
			Link:match[[<http://example.org/>; rel="start http://example.net/relation/other"]])
	end)
	it("Parses a Set-Cookie header", function()
		local Set_Cookie = lpeg.Ct(http.Set_Cookie) * EOF
		assert.same({"SID", "31d4d96e407aad42", {}}, Set_Cookie:match"SID=31d4d96e407aad42")
		assert.same({"SID", "", {}}, Set_Cookie:match"SID=")
		assert.same({"SID", "31d4d96e407aad42", {path="/"; domain="example.com"}},
			Set_Cookie:match"SID=31d4d96e407aad42; Path=/; Domain=example.com")
		assert.same({"SID", "31d4d96e407aad42", {
			path = "/";
			domain = "example.com";
			secure = true;
			expires = "Sun Nov  6 08:49:37 1994";
		}}, Set_Cookie:match"SID=31d4d96e407aad42; Path=/; Domain=example.com; Secure; Expires=Sun Nov  6 08:49:37 1994")
		-- Space before '='
		assert.same({"SID", "31d4d96e407aad42", {path = "/";}}, Set_Cookie:match"SID=31d4d96e407aad42; Path =/")
		-- Quoted cookie value
		assert.same({"SID", "31d4d96e407aad42", {path = "/";}}, Set_Cookie:match[[SID="31d4d96e407aad42"; Path=/]])
		-- Crazy whitespace
		assert.same({"SID", "31d4d96e407aad42", {path = "/";}}, Set_Cookie:match"SID  =   31d4d96e407aad42  ;   Path  =  /")
		assert.same({"SID", "31d4d96e407aad42", {["foo  bar"] = true;}},
			Set_Cookie:match"SID  =   31d4d96e407aad42  ;  foo  bar")
	end)
	it("Parses a Cookie header", function()
		local Cookie = http.Cookie * EOF
		assert.same({SID = "31d4d96e407aad42"}, Cookie:match"SID=31d4d96e407aad42")
		assert.same({SID = "31d4d96e407aad42"}, Cookie:match"SID = 31d4d96e407aad42")
		assert.same({SID = "31d4d96e407aad42", lang = "en-US"}, Cookie:match"SID=31d4d96e407aad42; lang=en-US")
	end)
	it("Parses a Content-Disposition header", function()
		local Content_Disposition = lpeg.Ct(http.Content_Disposition) * EOF
		assert.same({"foo", {}}, Content_Disposition:match"foo")
		assert.same({"foo", {filename="example"}}, Content_Disposition:match"foo; filename=example")
		assert.same({"foo", {filename="example"}}, Content_Disposition:match"foo; filename*=UTF-8''example")
	end)
	it("Parses a Strict-Transport-Security header", function()
		local sts_patt = http.Strict_Transport_Security * EOF
		assert.same({["max-age"] = "0"}, sts_patt:match("max-age=0"))
		assert.same({["max-age"] = "0"}, sts_patt:match("max-age = 0"))
		assert.same({["max-age"] = "0"}, sts_patt:match("Max-Age=0"))
		assert.same({["max-age"] = "0"; includesubdomains = true}, sts_patt:match("max-age=0;includeSubdomains"))
		assert.same({["max-age"] = "0"; includesubdomains = true}, sts_patt:match("max-age=0 ; includeSubdomains"))
		-- max-age is required
		assert.same(nil, sts_patt:match("foo=0"))
		-- Should fail to parse when duplicate field given.
		assert.same(nil, sts_patt:match("max-age=42; foo=0; foo=1"))
	end)
	it("Parses a Cache-Control header", function()
		local cc_patt = lpeg.Cf(lpeg.Ct(true) * http.Cache_Control, rawset) * EOF
		assert.same({public = true}, cc_patt:match("public"))
		assert.same({["no-cache"] = true}, cc_patt:match("no-cache"))
		assert.same({["max-age"] = "31536000"}, cc_patt:match("max-age=31536000"))
		assert.same({["max-age"] = "31536000", immutable = true}, cc_patt:match("max-age=31536000, immutable"))
		-- leading/trailing whitespace
		assert.same({public = true}, cc_patt:match("  public  "))
		assert.same({["max-age"] = "31536000", immutable = true}, cc_patt:match("   max-age=31536000    ,    immutable   "))
	end)
	it("Parses an WWW_Authenticate header", function()
		local WWW_Authenticate = lpeg.Ct(http.WWW_Authenticate) * EOF
		assert.same({{"Newauth"}}, WWW_Authenticate:match"Newauth")
		assert.same({{"Newauth", {realm = "apps"}}}, WWW_Authenticate:match[[Newauth realm="apps"]])
		assert.same({{"Newauth", {realm = "apps"}}}, WWW_Authenticate:match[[Newauth ReaLm="apps"]])
		assert.same({{"Newauth"}, {"Basic"}}, WWW_Authenticate:match"Newauth, Basic")
		assert.same({{"Newauth", {realm = "apps", type="1", title="Login to \"apps\""}}, {"Basic", {realm="simple"}}},
			WWW_Authenticate:match[[Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple"]])
	end)
	it("Parses a HPKP header", function()
		-- Example from RFC 7469 2.1.5
		local pkp_patt = lpeg.Ct(http.Public_Key_Pins) * EOF
		assert.same({
			{
				sha256 = {
					"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
					"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
				};
			}, {
				["max-age"] = "3000";
			}
		}, pkp_patt:match([[max-age=3000; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))

		-- max-age is compulsory
		assert.same(nil, pkp_patt:match([[pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))
	end)
	it("Parses a HPKP Report header", function()
		-- Example from RFC 7469 2.1.5
		local pkp_patt = lpeg.Ct(http.Public_Key_Pins_Report_Only) * EOF
		assert.same({
			{
				sha256 = {
					"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
					"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
				};
			}, {
				["max-age"] = "3000";
			}
		}, pkp_patt:match([[max-age=3000; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))
		-- max-age isn't compulsory
		assert.same({
			{
				sha256 = {
					"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
					"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
				};
			}, {
			}
		}, pkp_patt:match([[pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))
	end)
	it("Parses a Expect-Ct header", function()
		-- Examples from draft-ietf-httpbis-expect-ct-06 2.1.4
		local sts_patt = http.Expect_CT * EOF
		assert.same({["max-age"] = "86400", enforce = true}, sts_patt:match("max-age=86400, enforce"))
		assert.same({
			["max-age"] = "86400";
			["report-uri"] = "https://foo.example/report";
		}, sts_patt:match([[max-age=86400,report-uri="https://foo.example/report"]]))
		-- max-age is required
		assert.same(nil, sts_patt:match("foo=0"))
		-- Should fail to parse when duplicate field given
		assert.same(nil, sts_patt:match("max-age086400, foo=0, foo=1"))
	end)
end)
