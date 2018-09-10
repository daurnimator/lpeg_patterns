local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"
local http_utils = require "lpeg_patterns.http.util"

local Cmt = lpeg.Cmt
local P = lpeg.P

-- RFC 7469
local Public_Key_Directives = http_utils.directive * (http_core.OWS * P";" * http_core.OWS * http_utils.directive)^0
local function pkp_cmt(pins, t, k, v, ...)
	-- duplicates are allowed if the directive name starts with "pin-"
	local pin_name = k:match("^pin%-(.+)")
	if pin_name then
		local hashes = pins[pin_name]
		if hashes then
			hashes[#hashes+1] = v
		else
			hashes = {v}
			pins[pin_name] = hashes
		end
	else
		local old = t[k]
		if old then
			return false
		end
		t[k] = v
	end
	if ... then
		return pkp_cmt(pins, t, ...)
	else
		return true
	end
end
local Public_Key_Pins = Cmt(Public_Key_Directives, function(_, _, ...)
	local pins = {}
	local t = {}
	local ok = pkp_cmt(pins, t, ...)
	if ok and t["max-age"] then
		return true, pins, t
	end
end)
local Public_Key_Pins_Report_Only = Cmt(Public_Key_Directives, function(_, _, ...)
	local pins = {}
	local t = {}
	local ok = pkp_cmt(pins, t, ...)
	if ok then
		return true, pins, t
	end
end)

return {
	Public_Key_Pins = Public_Key_Pins;
	Public_Key_Pins_Report_Only = Public_Key_Pins_Report_Only;
}
