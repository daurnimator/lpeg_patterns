describe("lpeg_patterns.http.expect_ct", function()
	local http_expect_ct = require "lpeg_patterns.http.expect_ct"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a Expect-Ct header", function()
		-- Examples from draft-ietf-httpbis-expect-ct-06 2.1.4
		local sts_patt = http_expect_ct.Expect_CT * EOF
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
