describe("lpeg_patterns.http.cookie", function()
	local http_cookie = require "lpeg_patterns.http.cookie"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a Set-Cookie header", function()
		local Set_Cookie = lpeg.Ct(http_cookie.Set_Cookie) * EOF
		assert.same({"SID", "31d4d96e407aad42", {}}, Set_Cookie:match"SID=31d4d96e407aad42")
		assert.same({"SID", "", {}}, Set_Cookie:match"SID=")
		assert.same({"SID", "31d4d96e407aad42", {path="/"; domain="example.com"}},
			Set_Cookie:match"SID=31d4d96e407aad42; Path=/; Domain=example.com")
		assert.same({"SID", "31d4d96e407aad42", {
			path = "/";
			domain = "example.com";
			secure = true;
			expires = "Sun Nov  6 08:49:37 1994";
		}}, Set_Cookie:match"SID=31d4d96e407aad42; Path=/; Domain=example.com; Secure; Expires=Sun Nov  6 08:49:37 1994")
		-- Space before '='
		assert.same({"SID", "31d4d96e407aad42", {path = "/";}}, Set_Cookie:match"SID=31d4d96e407aad42; Path =/")
		-- Quoted cookie value
		assert.same({"SID", "31d4d96e407aad42", {path = "/";}}, Set_Cookie:match[[SID="31d4d96e407aad42"; Path=/]])
		-- Crazy whitespace
		assert.same({"SID", "31d4d96e407aad42", {path = "/";}}, Set_Cookie:match"SID  =   31d4d96e407aad42  ;   Path  =  /")
		assert.same({"SID", "31d4d96e407aad42", {["foo  bar"] = true;}},
			Set_Cookie:match"SID  =   31d4d96e407aad42  ;  foo  bar")
	end)
	it("Parses a Cookie header", function()
		local Cookie = http_cookie.Cookie * EOF
		assert.same({SID = "31d4d96e407aad42"}, Cookie:match"SID=31d4d96e407aad42")
		assert.same({SID = "31d4d96e407aad42"}, Cookie:match"SID = 31d4d96e407aad42")
		assert.same({SID = "31d4d96e407aad42", lang = "en-US"}, Cookie:match"SID=31d4d96e407aad42; lang=en-US")
	end)
end)
