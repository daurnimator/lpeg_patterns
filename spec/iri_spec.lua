local lpeg = require "lpeg"
describe("IRI", function()
	local iri_lib = require "lpeg_patterns.iri"
	local absolute_IRI = iri_lib.absolute_IRI * lpeg.P(-1)
	local IRI = iri_lib.IRI * lpeg.P(-1)
	local iref = iri_lib.IRI_reference * lpeg.P(-1)
	local ipath = iri_lib.ipath * lpeg.P(-1)
	it("Should break down full IRIs correctly", function()
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path", query="query", fragment="fragment"},
			IRI:match "scheme://userinfo@host:1234/path?query#fragment")
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path", query="query"},
			IRI:match "scheme://userinfo@host:1234/path?query")
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path"},
			IRI:match "scheme://userinfo@host:1234/path")
		assert.same({scheme="scheme", host="host", port=1234, path="/path"},
			IRI:match "scheme://host:1234/path")
		assert.same({scheme="scheme", host="host", path="/path"},
			IRI:match "scheme://host/path")
		assert.same({scheme="scheme", path="/path"},
			IRI:match "scheme:///path")
		assert.same({scheme="scheme"},
			IRI:match "scheme://")
	end)
	it("Normalises to lower case scheme", function()
		assert.same({scheme="scheme"}, IRI:match "Scheme://")
		assert.same({scheme="scheme"}, IRI:match "SCHEME://")
	end)
	it("shouldn't allow fragments when using absolute_IRI", function()
		assert.falsy(absolute_IRI:match "scheme://userinfo@host:1234/path?query#fragment")
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path", query="query"},
			absolute_IRI:match "scheme://userinfo@host:1234/path?query")
	end)
	it("Should break down relative IRIs correctly", function()
		assert.same({scheme="scheme", userinfo="userinfo", host="host", port=1234, path="/path", query="query", fragment="fragment"},
			iref:match "scheme://userinfo@host:1234/path?query#fragment")
		assert.same({userinfo="userinfo", host="host", port=1234, path="/path", query="query", fragment="fragment"},
			iref:match "//userinfo@host:1234/path?query#fragment")
		assert.same({host="host", port=1234, path="/path", query="query", fragment="fragment"},
			iref:match "//host:1234/path?query#fragment")
		assert.same({host="host", path="/path", query="query", fragment="fragment"},
			iref:match "//host/path?query#fragment")
		assert.same({path="/path", query="query", fragment="fragment"},
			iref:match "///path?query#fragment")
		assert.same({path="/path", query="query", fragment="fragment"},
			iref:match "/path?query#fragment")
		assert.same({path="/path", fragment="fragment"},
			iref:match "/path#fragment")
		assert.same({path="/path"},
			iref:match "/path")
		assert.same({},
			iref:match "")
		assert.same({query="query"},
			iref:match "?query")
		assert.same({fragment="fragment"},
			iref:match "#fragment")
	end)
	it("Should match file urls", function()
		assert.same({scheme="file", path="/var/log/messages"}, IRI:match "file:///var/log/messages")
		assert.same({scheme="file", path="/C:/Windows/"}, IRI:match "file:///C:/Windows/")
	end)
	it("Should decode unreserved percent characters path", function()
		assert.same("/underscore_character", ipath:match "/underscore%5Fcharacter")
		assert.same("/null%00byte", ipath:match "/null%00byte")
	end
)	it("Should fail on incorrect percent characters", function()
		assert.falsy(ipath:match "/bad%x0percent")
		assert.falsy(ipath:match "/%s")
	end)
	it("Should not introduce ambiguiuty by decoding percent encoded entities", function()
		assert.same({query="query%26with&ampersand"}, iref:match "?query%26with&ampersand")
	end)
	it("Should decode unreserved percent characters in query and fragment", function()
		assert.same({query="query%20with_escapes"}, iref:match "?query%20with%5Fescapes")
		assert.same({fragment="fragment%20with_escapes"}, iref:match "#fragment%20with%5Fescapes")
	end)
	it("Should match localhost", function()
		assert.same({host="localhost"}, iref:match "//localhost")
		assert.same({host="localhost"}, iref:match "//LOCALHOST")
		assert.same({host="localhost"}, iref:match "//l%4FcAlH%6fSt")
		assert.same({host="localhost", port=8000}, iref:match "//localhost:8000")
		assert.same({scheme="http", host="localhost", port=8000}, IRI:match "http://localhost:8000")
	end)
	it("Should work with IPv6", function()
		assert.same({host="0:0:0:0:0:0:0:1"}, iref:match "//[::1]")
		assert.same({host="0:0:0:0:0:0:0:1", port=80}, iref:match "//[::1]:80")
	end)
	it("IPvFuture", function()
		assert.same({host="v4.2", port=80}, iref:match "//[v4.2]:80")
		assert.same({host="v4.2", port=80}, iref:match "//[V4.2]:80")
	end)
	it("Should work with IPv6 zone local addresses", function()
		assert.same({host="0:0:0:0:0:0:0:1%eth0"}, iref:match "//[::1%25eth0]")
	end)
	it("Relative IRI does not match authority when scheme is missing", function()
		assert.same({path="example.com/"}, iref:match "example.com/") -- should end up in path
		assert.same({scheme="scheme", host="example.com", path="/"}, iref:match "scheme://example.com/")
	end)
	it("Should work with mailto URIs", function()
		assert.same({scheme="mailto", path="user@example.com"}, IRI:match "mailto:user@example.com")
		assert.same({scheme="mailto", path="someone@example.com,someoneelse@example.com"},
			IRI:match "mailto:someone@example.com,someoneelse@example.com")
		assert.same({scheme="mailto", path="user@example.com", query="subject=This%20is%20the%20subject&cc=someone_else@example.com&body=This%20is%20the%20body"},
			IRI:match "mailto:user@example.com?subject=This%20is%20the%20subject&cc=someone_else@example.com&body=This%20is%20the%20body")

		-- Examples from RFC-6068
		-- Section 6.1
		assert.same({scheme="mailto", path="chris@example.com"}, IRI:match "mailto:chris@example.com")
		assert.same({scheme="mailto", path="infobot@example.com", query="subject=current-issue"},
			IRI:match "mailto:infobot@example.com?subject=current-issue")
		assert.same({scheme="mailto", path="infobot@example.com", query="body=send%20current-issue"},
			IRI:match "mailto:infobot@example.com?body=send%20current-issue")
		assert.same({scheme="mailto", path="infobot@example.com", query="body=send%20current-issue%0D%0Asend%20index"},
			IRI:match "mailto:infobot@example.com?body=send%20current-issue%0D%0Asend%20index")
		assert.same({scheme="mailto", path="list@example.org", query="In-Reply-To=%3C3469A91.D10AF4C@example.com%3E"},
			IRI:match "mailto:list@example.org?In-Reply-To=%3C3469A91.D10AF4C@example.com%3E")
		assert.same({scheme="mailto", path="majordomo@example.com", query="body=subscribe%20bamboo-l"},
			IRI:match "mailto:majordomo@example.com?body=subscribe%20bamboo-l")
		assert.same({scheme="mailto", path="joe@example.com", query="cc=bob@example.com&body=hello"},
			IRI:match "mailto:joe@example.com?cc=bob@example.com&body=hello")
		assert.same({scheme="mailto", path="gorby%25kremvax@example.com"}, IRI:match "mailto:gorby%25kremvax@example.com")
		assert.same({scheme="mailto", path="unlikely%3Faddress@example.com", query="blat=foop"},
			IRI:match "mailto:unlikely%3Faddress@example.com?blat=foop")
		assert.same({scheme="mailto", path="Mike%26family@example.org"}, IRI:match "mailto:Mike%26family@example.org")
		-- Section 6.2
		assert.same({scheme="mailto", path=[[%22not%40me%22@example.org]]}, IRI:match "mailto:%22not%40me%22@example.org")
		assert.same({scheme="mailto", path=[[%22oh%5C%5Cno%22@example.org]]}, IRI:match "mailto:%22oh%5C%5Cno%22@example.org")
		assert.same({scheme="mailto", path=[[%22%5C%5C%5C%22it's%5C%20ugly%5C%5C%5C%22%22@example.org]]},
			IRI:match "mailto:%22%5C%5C%5C%22it's%5C%20ugly%5C%5C%5C%22%22@example.org")
	end)
	it("Should work with xmpp URIs", function()
		-- Examples from RFC-5122
		assert.same({scheme="xmpp", path="node@example.com"}, IRI:match "xmpp:node@example.com")
		assert.same({scheme="xmpp", userinfo="guest", host="example.com"}, IRI:match "xmpp://guest@example.com")
		assert.same({scheme="xmpp", userinfo="guest", host="example.com", path="/support@example.com", query="message"},
			IRI:match "xmpp://guest@example.com/support@example.com?message")
		assert.same({scheme="xmpp", path="support@example.com", query="message"}, IRI:match "xmpp:support@example.com?message")

		assert.same({scheme="xmpp", path="example-node@example.com"}, IRI:match "xmpp:example-node@example.com")
		assert.same({scheme="xmpp", path="example-node@example.com/some-resource"}, IRI:match "xmpp:example-node@example.com/some-resource")
		assert.same({scheme="xmpp", path="example.com"}, IRI:match "xmpp:example.com")
		assert.same({scheme="xmpp", path="example-node@example.com", query="message"}, IRI:match "xmpp:example-node@example.com?message")
		assert.same({scheme="xmpp", path="example-node@example.com", query="message;subject=Hello%20World"},
			IRI:match "xmpp:example-node@example.com?message;subject=Hello%20World")
		assert.same({scheme="xmpp", path=[[nasty!%23$%25()*+,-.;=%3F%5B%5C%5D%5E_%60%7B%7C%7D~node@example.com]]},
			IRI:match "xmpp:nasty!%23$%25()*+,-.;=%3F%5B%5C%5D%5E_%60%7B%7C%7D~node@example.com")
		assert.same({scheme="xmpp", path=[[node@example.com/repulsive%20!%23%22$%25&'()*+,-.%2F:;%3C=%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~resource]]},
			IRI:match [[xmpp:node@example.com/repulsive%20!%23%22$%25&'()*+,-.%2F:;%3C=%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~resource]])
		assert.same({scheme="xmpp", path="ji%C5%99i@%C4%8Dechy.example/v%20Praze"}, IRI:match "xmpp:ji%C5%99i@%C4%8Dechy.example/v%20Praze")
	end)
end)
