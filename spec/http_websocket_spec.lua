describe("lpeg_patterns.http.websocket", function()
	local http_websocket = require "lpeg_patterns.http.websocket"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a Sec-WebSocket-Extensions header", function()
		local Sec_WebSocket_Extensions = lpeg.Ct(http_websocket.Sec_WebSocket_Extensions) * EOF
		assert.same({{"foo", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo")
		assert.same({{"foo", parameters = {}}, {"bar", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo, bar")
		assert.same({{"foo", parameters = {hello = true; world = "extension"}}, {"bar", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo;hello;world=extension, bar")
		assert.same({{"foo", parameters = {hello = true; world = "extension"}}, {"bar", parameters = {}}},
			Sec_WebSocket_Extensions:match"foo;hello;world=\"extension\", bar")
		-- quoted strings must be valid tokens
		assert.falsy(Sec_WebSocket_Extensions:match"foo;hello;world=\"exte\\\"nsion\", bar")
	end)
	it("Parses a Sec_WebSocket-Version-Client header", function()
		local Sec_WebSocket_Version_Client = http_websocket.Sec_WebSocket_Version_Client * EOF
		assert.same(1, Sec_WebSocket_Version_Client:match"1")
		assert.same(100, Sec_WebSocket_Version_Client:match"100")
		assert.same(255, Sec_WebSocket_Version_Client:match"255")
		assert.falsy(Sec_WebSocket_Version_Client:match"0")
		assert.falsy(Sec_WebSocket_Version_Client:match"256")
		assert.falsy(Sec_WebSocket_Version_Client:match"1.2")
		assert.falsy(Sec_WebSocket_Version_Client:match"090")
	end)
end)
