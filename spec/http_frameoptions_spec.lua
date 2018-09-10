describe("lpeg_patterns.http.frameoptions", function()
	local http_frameoptions = require "lpeg_patterns.http.frameoptions"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses an X-Frame-Options header", function()
		local X_Frame_Options = lpeg.Ct(http_frameoptions.X_Frame_Options) * EOF
		assert.same({"deny"}, X_Frame_Options:match("deny"))
		assert.same({"deny"}, X_Frame_Options:match("DENY"))
		assert.same({"deny"}, X_Frame_Options:match("dEnY"))
		assert.same({"http://example.com"}, X_Frame_Options:match("Allow-From http://example.com"))
	end)
end)
