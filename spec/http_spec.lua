describe("http patterns", function()
	local http = require "lpeg_patterns.http"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
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
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}}, Content_Type:match([[text/html;charset=utf-8]]))
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}}, Content_Type:match([[Text/HTML;Charset="utf-8"]]))
		assert.same({ type = "text", subtype = "html", parameters = {charset="utf-8"}}, Content_Type:match([[text/html; charset="utf-8"]]))
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
end)
