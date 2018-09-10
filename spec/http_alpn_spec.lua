describe("lpeg_patterns.http.alpn", function()
	local http_alpn = require "lpeg_patterns.http.alpn"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	local protocol_id = http_alpn.protocol_id * EOF
	it("unescapes an ALPN protocol id correctly", function()
		assert.same("foo", protocol_id:match("foo"))
		-- percent encoded chars
		assert.same(" ", protocol_id:match("%20")) -- space
		assert.same("%", protocol_id:match("%25")) -- %
	end)
	it("must not decode to character that didn't need to be escaped", function()
		assert.same(nil, protocol_id:match("%41")) -- a
		assert.same(nil, protocol_id:match("%26")) -- &
	end)
	it("must be 2 digit hex", function()
		assert.same(nil, protocol_id:match("%2"))
	end)
	it("must be uppercase hex", function()
		assert.same(nil, protocol_id:match("%1a"))
	end)
end)
