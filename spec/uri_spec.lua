local lpeg=require "lpeg"
local uri_lib=require "lpeg_patterns.uri"

describe("URI", function()
	local uri = uri_lib.uri * lpeg.P(-1)
	local ref = uri_lib.uri_reference * lpeg.P(-1)
	local path = uri_lib.path * lpeg.P(-1)
	it("Should break down full URIs correctly", function()
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path", query="query", fragment="fragment"},
			uri:match "scheme://userinfo@host:1234/path?query#fragment")
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path", query="query"},
			uri:match "scheme://userinfo@host:1234/path?query")
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path"},
			uri:match "scheme://userinfo@host:1234/path")
		assert.same({scheme="scheme", host="host", port=1234, path="/path"},
			uri:match "scheme://host:1234/path")
		assert.same({scheme="scheme", host="host", path="/path"},
			uri:match "scheme://host/path")
		assert.same({scheme="scheme", path="/path"},
			uri:match "scheme:///path")
		assert.same({scheme="scheme", path=""},
			uri:match "scheme://")
	end)
	it("Should break down relative URIs correctly", function()
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path", query="query", fragment="fragment"},
			ref:match "scheme://userinfo@host:1234/path?query#fragment")
		assert.same({userinfo="userinfo", host="host", port=1234, path="/path", query="query", fragment="fragment"},
			ref:match "//userinfo@host:1234/path?query#fragment")
		assert.same({host="host", port=1234, path="/path", query="query", fragment="fragment"},
			ref:match "//host:1234/path?query#fragment")
		assert.same({host="host", path="/path", query="query", fragment="fragment"},
			ref:match "//host/path?query#fragment")
		assert.same({path="/path", query="query", fragment="fragment"},
			ref:match "///path?query#fragment")
		assert.same({path="/path", query="query", fragment="fragment"},
			ref:match "/path?query#fragment")
		assert.same({path="/path", fragment="fragment"},
			ref:match "/path#fragment")
		assert.same({path="/path"},
			ref:match "/path")
		assert.same({},
			ref:match "")
		assert.same({query="query"},
			ref:match "?query")
		assert.same({fragment="fragment"},
			ref:match "#fragment")
	end)
	it("Should match file urls", function()
		assert.same({scheme="file", path="/var/log/messages"}, uri:match "file:///var/log/messages")
		assert.same({scheme="file", path="/C:/Windows/"}, uri:match "file:///C:/Windows/")
	end)
	it("Should decode percent characters #path", function()
		assert.same("/space character", path:match "/space%20character")
		assert.same("/null\0byte", path:match "/null%00byte")

		assert.falsy(path:match "/bad%x0percent")
	end)
	it("Should match localhost", function()
		assert.same({host="localhost", path=""}, ref:match "//localhost")
		assert.same({host="localhost", port=8000, path=""}, ref:match "//localhost:8000")
		assert.same({scheme="http", host="localhost", port=8000, path=""}, uri:match "http://localhost:8000")
	end)
	it("Should work with IPv6", function()
		assert.same({host="0:0:0:0:0:0:0:1", path=""}, ref:match "//[::1]")
		assert.same({host="0:0:0:0:0:0:0:1", port=80, path=""}, ref:match "//[::1]:80")
	end)
	it("IPvFuture", function()
		assert.same({host="v4.2", port=80, path=""}, ref:match "//[v4.2]:80")
	end)
	it("Should work with IPv6 zone local addresses", function()
		assert.same({host="0:0:0:0:0:0:0:1%eth0", path=""}, ref:match "//[::1%25eth0]")
	end)
	it("Relative URI does not match authority when scheme is missing", function()
		assert.same({path="example.com/"}, ref:match "example.com/") -- should end up in path
		assert.same({scheme="scheme", host="example.com", path="/"}, ref:match "scheme://example.com/")
	end)
	it("Should work with mailto URIs", function()
		assert.same({scheme="mailto", path="user@example.com"}, uri:match "mailto:user@example.com")
		assert.same({scheme="mailto", path="someone@example.com,someoneelse@example.com"}, uri:match "mailto:someone@example.com,someoneelse@example.com")

		-- Examples from RFC6068
		-- Section 6.1
		assert.same({scheme="mailto", path="chris@example.com"}, uri:match "mailto:chris@example.com")
		assert.same({scheme="mailto", path="infobot@example.com", query="subject=current-issue"}, uri:match "mailto:infobot@example.com?subject=current-issue")
		assert.same({scheme="mailto", path="joe@example.com", query="cc=bob@example.com&body=hello"}, uri:match "mailto:joe@example.com?cc=bob@example.com&body=hello")
		assert.same({scheme="mailto", path="gorby%kremvax@example.com"}, uri:match "mailto:gorby%25kremvax@example.com")
		assert.same({scheme="mailto", path="unlikely?address@example.com", query="blat=foop"}, uri:match "mailto:unlikely%3Faddress@example.com?blat=foop")
		assert.same({scheme="mailto", path="Mike&family@example.org"}, uri:match "mailto:Mike%26family@example.org")
		-- Section 6.2
		assert.same({scheme="mailto", path=[["not@me"@example.org]]}, uri:match "mailto:%22not%40me%22@example.org")
		assert.same({scheme="mailto", path=[["oh\\no"@example.org]]}, uri:match "mailto:%22oh%5C%5Cno%22@example.org")
		assert.same({scheme="mailto", path=[["\\\"it's\ ugly\\\""@example.org]]}, uri:match "mailto:%22%5C%5C%5C%22it's%5C%20ugly%5C%5C%5C%22%22@example.org")
	end)
end)

describe("Sane URI", function()
	local sane_uri = uri_lib.sane_uri
	it("Not match the empty string", function()
		assert.falsy ( sane_uri:match "" )
	end)
	it("Not match misc words", function()
		assert.falsy ( sane_uri:match "the quick fox jumped over the lazy dog." )
	end)
	it("Not match numbers", function()
		assert.falsy( sane_uri:match "123" )
		assert.falsy( sane_uri:match "17.3" )
		assert.falsy( sane_uri:match "17.3234" )
		assert.falsy( sane_uri:match "17.3234" )
	end)
	it("Should match a host when no // present", function()
		assert.same({host="example.com"}, sane_uri:match "example.com")
	end)
	it("Match a scheme without a //", function()
		assert.same({scheme="scheme", host="example.com"}, sane_uri:match "scheme:example.com")
	end)
end)
