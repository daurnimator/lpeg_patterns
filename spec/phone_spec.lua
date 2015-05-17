local lpeg = require "lpeg"

describe("Phone numbers", function()
	local phone = require "lpeg_patterns.phone"
	local any_only = phone.phone * lpeg.P(-1)

	it("NANP (North America Numbering Plan)", function()
		assert.truthy(any_only:match"+12345678900")
		assert.truthy(any_only:match"+1 (234) 567-8900")

		assert.truthy(phone.USA:match"1 (234) 567-8900")
		assert.truthy(phone.USA:match"(234) 567-8900")
		assert.falsy(phone.USA:match"2 (234) 567-8900")

		-- N11 not allowed
		assert.falsy(any_only:match"+12345118900")
		-- N9X not allowed
		assert.falsy(any_only:match"+12345978900")
		-- 37X not allowed
		assert.falsy(any_only:match"+12343778900")
		-- 96X not allowed
		assert.falsy(any_only:match"+12349678900")
	end)

	it("Australian numbers", function()
		assert.truthy(phone.Australia:match"0390000000")
		assert.truthy(phone.Australia:match"3 90000000")
		assert.truthy(phone.Australia:match"3 9000 0000")
		assert.truthy(phone.Australia:match"400 000 000")

		assert.truthy(any_only:match"+61390000000")
		assert.truthy(any_only:match"+61 3 90000000")
		assert.truthy(any_only:match"+61 3 9000 0000")
		assert.truthy(any_only:match"+61 400 000 000")

		assert.falsy(any_only:match"+610390000000")
	end)
end)
