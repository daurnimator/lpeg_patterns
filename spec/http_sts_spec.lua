describe("lpeg_patterns.http.sts", function()
	local http_sts = require "lpeg_patterns.http.sts"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a Strict-Transport-Security header", function()
		local sts_patt = http_sts.Strict_Transport_Security * EOF
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
end)
