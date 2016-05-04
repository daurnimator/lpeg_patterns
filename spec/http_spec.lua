describe("http patterns", function()
	local http = require "lpeg_patterns.http"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses an Origin header", function()
		local Origin = lpeg.Ct(http.Origin) * EOF
		assert.same({}, Origin:match("null"))
		assert.same({"http://example.com"}, Origin:match("http://example.com"))
		assert.same({"http://example.com", "https://foo.org"}, Origin:match("http://example.com https://foo.org"))
	end)
	it("Splits a request line", function()
		local request_line = lpeg.Ct(http.request_line) * EOF
		assert.same({"GET", "/", 1.0}, request_line:match("GET / HTTP/1.0\r\n"))
		assert.same({"OPTIONS", "*", 1.1}, request_line:match("OPTIONS * HTTP/1.1\r\n"))
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
		assert.same({ type = "foo", subtype = "bar", parameters = {}}, Content_Type:match("foo/bar"))
		assert.same({ type = "foo", subtype = "bar", parameters = {param="value"}}, Content_Type:match("foo/bar;param=value"))
		-- Examples from RFC7231 3.1.1.1.
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}}, Content_Type:match([[text/html;charset=utf-8]]))
		-- assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}}, Content_Type:match([[text/html;charset=UTF-8]]))
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}}, Content_Type:match([[Text/HTML;Charset="utf-8"]]))
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}}, Content_Type:match([[text/html; charset="utf-8"]]))
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
		assert.same({{"foo", parameters = {}}}, Sec_WebSocket_Extensions:match"foo")
		assert.same({{"foo", parameters = {}}, {"bar", parameters = {}}}, Sec_WebSocket_Extensions:match"foo, bar")
		assert.same({{"foo", parameters = {hello = true; world = "extension"}}, {"bar", parameters = {}}}, Sec_WebSocket_Extensions:match"foo;hello;world=extension, bar")
		assert.same({{"foo", parameters = {hello = true; world = "extension"}}, {"bar", parameters = {}}}, Sec_WebSocket_Extensions:match"foo;hello;world=\"extension\", bar")
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
	it("Parses a Set-Cookie header", function()
		local Set_Cookie = lpeg.Ct(http.Set_Cookie) * EOF
		assert.same({"SID", "31d4d96e407aad42", {}}, Set_Cookie:match"SID=31d4d96e407aad42")
		assert.same({"SID", "31d4d96e407aad42", {Path="/"; Domain="example.com"}}, Set_Cookie:match"SID=31d4d96e407aad42; Path=/; Domain=example.com")
		assert.same({"SID", "31d4d96e407aad42", {
			Path = "/";
			Domain = "example.com";
			Secure = true;
			Expires = "Sun Nov  6 08:49:37 1994";
		}}, Set_Cookie:match"SID=31d4d96e407aad42; Path=/; Domain=example.com; Secure; Expires=Sun Nov  6 08:49:37 1994")
		-- Space before '='
		assert.same({"SID", "31d4d96e407aad42", {Path = "/";}}, Set_Cookie:match"SID=31d4d96e407aad42; Path =/")
		-- Quoted cookie value
		assert.same({"SID", "31d4d96e407aad42", {Path = "/";}}, Set_Cookie:match[[SID="31d4d96e407aad42"; Path=/]])
	end)
	it("Parses a Cookie header", function()
		local Cookie = http.Cookie * EOF
		assert.same({SID = "31d4d96e407aad42"}, Cookie:match"SID=31d4d96e407aad42")
		assert.same({SID = "31d4d96e407aad42", lang = "en-US"}, Cookie:match"SID=31d4d96e407aad42; lang=en-US")
	end)
end)
