describe("lpeg_patterns.http.alpn", function()
	local utf8 = require "lpeg_patterns.utf8"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	local UTF8_char = lpeg.C(utf8.UTF8_char) * EOF
	it("works", function()
		assert.same("f", UTF8_char:match("f"))
		assert.same("日", UTF8_char:match("日"))
	end)
	it("must not match invalid sequences", function()
		assert.same(nil, UTF8_char:match("\128"))
		assert.same(nil, UTF8_char:match("\255"))
	end)
end)
