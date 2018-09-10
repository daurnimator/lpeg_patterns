describe("lpeg_patterns.http.origin", function()
	local http_origin = require "lpeg_patterns.http.origin"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses an Origin header", function()
		local Origin = lpeg.Ct(http_origin.Origin) * EOF
		assert.same({}, Origin:match("null"))
		assert.same({"http://example.com"}, Origin:match("http://example.com"))
		assert.same({"http://example.com", "https://foo.org"}, Origin:match("http://example.com https://foo.org"))
	end)
end)
