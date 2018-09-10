describe("lpeg_patterns.http.slug", function()
	local http_slug = require "lpeg_patterns.http.slug"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a SLUG header", function()
		local SLUG = http_slug.SLUG * EOF
		assert.same("foo", SLUG:match("foo"))
		assert.same("foo bar", SLUG:match("foo bar"))
		assert.same("foo bar", SLUG:match("foo  bar"))
		assert.same("foo   bar", SLUG:match("foo %20 bar"))
	end)
end)
