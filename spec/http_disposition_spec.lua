describe("lpeg_patterns.http.disposition", function()
	local http_disposition = require "lpeg_patterns.http.disposition"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a Content-Disposition header", function()
		local Content_Disposition = lpeg.Ct(http_disposition.Content_Disposition) * EOF
		assert.same({"foo", {}}, Content_Disposition:match"foo")
		assert.same({"foo", {filename="example"}}, Content_Disposition:match"foo; filename=example")
		assert.same({"foo", {filename="example"}}, Content_Disposition:match"foo; filename*=UTF-8''example")
	end)
end)
