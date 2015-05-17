local lpeg = require "lpeg"

describe("IPv6 Addresses", function()
	local IPv6address = require "lpeg_patterns.IPv6".IPv6address
	local IPv6address_only = IPv6address * lpeg.P(-1)
	it("Addresses are parsed correctly", function()
		local function same(str, ...)
			local addr = IPv6address_only:match(str)
			assert(addr, "Could not parse " .. str)
			assert.same({...}, {addr:unpack()})
		end
		same("::", 0,0,0,0,0,0,0,0)
		same("::0.0.0.0", 0,0,0,0,0,0,0,0)
		same("::0:0.0.0.0", 0,0,0,0,0,0,0,0)
		same("0::0.0.0.0", 0,0,0,0,0,0,0,0)
		same("::1", 0,0,0,0,0,0,0,1)
		same("ff02::1", 0xff02,0,0,0,0,0,0,1)
		same("2001:0db8:85a3:0042:1000:8a2e:0370:7334",
			0x2001, 0x0db8, 0x85a3, 0x0042, 0x1000, 0x8a2e, 0x0370, 0x7334)
		same("::FFFF:204.152.189.116", 0, 0, 0, 0, 0, 0xFFFF, 204*256+152, 189*256+116)
	end)
	it("Non-addresses fail parsing", function()
		assert.falsy(IPv6address_only:match"")
		assert.falsy(IPv6address_only:match"not an ip")
		assert.falsy(IPv6address_only:match"::x")
		assert.falsy(IPv6address_only:match"x::")
		assert.falsy(IPv6address_only:match":::")
		assert.falsy(IPv6address_only:match":1::")
		 -- Two ::
		assert.falsy(IPv6address_only:match"1234::5678::")
		-- Invalid IPv4
		assert.falsy(IPv6address_only:match"::FFFF:0.0.0")
		assert.falsy(IPv6address_only:match"::FFFF:0.999.0.0")
	end)
end)
