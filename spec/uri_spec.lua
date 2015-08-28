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
	end)
	it("Should fail on incorrect percent characters", function()
		assert.falsy(path:match "/bad%x0percent")
		assert.falsy(path:match "/%s")
	end)
	it("Should decode percent characters in query and fragment", function()
		assert.same({query="query with/escapes"}, ref:match "?query%20with%2Fescapes")
		assert.same({fragment="fragment with/escapes"}, ref:match "#fragment%20with%2Fescapes")
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
		assert.same({scheme="mailto", path="someone@example.com,someoneelse@example.com"},
			uri:match "mailto:someone@example.com,someoneelse@example.com")
		assert.same({scheme="mailto", path="user@example.com", query="subject=This is the subject&cc=someone_else@example.com&body=This is the body"},
			uri:match "mailto:user@example.com?subject=This%20is%20the%20subject&cc=someone_else@example.com&body=This%20is%20the%20body")

		-- Examples from RFC-6068
		-- Section 6.1
		assert.same({scheme="mailto", path="chris@example.com"}, uri:match "mailto:chris@example.com")
		assert.same({scheme="mailto", path="infobot@example.com", query="subject=current-issue"},
			uri:match "mailto:infobot@example.com?subject=current-issue")
		assert.same({scheme="mailto", path="infobot@example.com", query="body=send current-issue"},
			uri:match "mailto:infobot@example.com?body=send%20current-issue")
		assert.same({scheme="mailto", path="infobot@example.com", query="body=send current-issue\r\nsend index"},
			uri:match "mailto:infobot@example.com?body=send%20current-issue%0D%0Asend%20index")
		assert.same({scheme="mailto", path="list@example.org", query="In-Reply-To=<3469A91.D10AF4C@example.com>"},
			uri:match "mailto:list@example.org?In-Reply-To=%3C3469A91.D10AF4C@example.com%3E")
		assert.same({scheme="mailto", path="majordomo@example.com", query="body=subscribe bamboo-l"},
			uri:match "mailto:majordomo@example.com?body=subscribe%20bamboo-l")
		assert.same({scheme="mailto", path="joe@example.com", query="cc=bob@example.com&body=hello"},
			uri:match "mailto:joe@example.com?cc=bob@example.com&body=hello")
		assert.same({scheme="mailto", path="gorby%kremvax@example.com"}, uri:match "mailto:gorby%25kremvax@example.com")
		assert.same({scheme="mailto", path="unlikely?address@example.com", query="blat=foop"},
			uri:match "mailto:unlikely%3Faddress@example.com?blat=foop")
		assert.same({scheme="mailto", path="Mike&family@example.org"}, uri:match "mailto:Mike%26family@example.org")
		-- Section 6.2
		assert.same({scheme="mailto", path=[["not@me"@example.org]]}, uri:match "mailto:%22not%40me%22@example.org")
		assert.same({scheme="mailto", path=[["oh\\no"@example.org]]}, uri:match "mailto:%22oh%5C%5Cno%22@example.org")
		assert.same({scheme="mailto", path=[["\\\"it's\ ugly\\\""@example.org]]},
			uri:match "mailto:%22%5C%5C%5C%22it's%5C%20ugly%5C%5C%5C%22%22@example.org")
	end)
	it("Should work with xmpp URIs", function()
		-- Examples from RFC-5122
		assert.same({scheme="xmpp", path="node@example.com"}, uri:match "xmpp:node@example.com")
		assert.same({scheme="xmpp", userinfo="guest", host="example.com", path=""}, uri:match "xmpp://guest@example.com")
		assert.same({scheme="xmpp", userinfo="guest", host="example.com", path="/support@example.com", query="message"},
			uri:match "xmpp://guest@example.com/support@example.com?message")
		assert.same({scheme="xmpp", path="support@example.com", query="message"}, uri:match "xmpp:support@example.com?message")

		assert.same({scheme="xmpp", path="example-node@example.com"}, uri:match "xmpp:example-node@example.com")
		assert.same({scheme="xmpp", path="example-node@example.com/some-resource"}, uri:match "xmpp:example-node@example.com/some-resource")
		assert.same({scheme="xmpp", path="example.com"}, uri:match "xmpp:example.com")
		assert.same({scheme="xmpp", path="example-node@example.com", query="message"}, uri:match "xmpp:example-node@example.com?message")
		assert.same({scheme="xmpp", path="example-node@example.com", query="message;subject=Hello World"},
			uri:match "xmpp:example-node@example.com?message;subject=Hello%20World")
		assert.same({scheme="xmpp", path=[[nasty!#$%()*+,-.;=?[\]^_`{|}~node@example.com]]},
			uri:match "xmpp:nasty!%23$%25()*+,-.;=%3F%5B%5C%5D%5E_%60%7B%7C%7D~node@example.com")
		assert.same({scheme="xmpp", path=[[node@example.com/repulsive !#"$%&'()*+,-./:;<=>?@[\]^_`{|}~resource]]},
			uri:match [[xmpp:node@example.com/repulsive%20!%23%22$%25&'()*+,-.%2F:;%3C=%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~resource]])
		assert.same({scheme="xmpp", path="jiři@čechy.example/v Praze"}, uri:match "xmpp:ji%C5%99i@%C4%8Dechy.example/v%20Praze")
	end)
end)

describe("Sane URI", function()
	local sane_uri = uri_lib.sane_uri
	it("Not match the empty string", function()
		assert.falsy ( sane_uri:match "" )
	end)
	it("Not match misc words", function()
		assert.falsy ( sane_uri:match "localhost" )
		assert.falsy ( sane_uri:match "//localhost" )
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
	it("Will match up to but not including a close parenthsis with empty path", function()
		assert.same({scheme="scheme", host="example.com"}, sane_uri:match "scheme:example.com)")
	end)
end)
