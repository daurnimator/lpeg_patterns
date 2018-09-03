local lpeg = require "lpeg"
local C = lpeg.C
local P = lpeg.P
local S = lpeg.S

local function case_insensitive(str)
	local patt = P(true)
	for i=1, #str do
		local c = str:sub(i, i)
		patt = patt * S(c:upper() .. c:lower())
	end
	return patt
end

local function no_rich_capture(patt)
	return C(patt) / function(a) return a end
end

local function read_hex(hex_num)
	return tonumber(hex_num, 16)
end

local safe_tonumber do -- locale independent tonumber function
	local tolocale
	local function updatelocale()
		local decpoint = string.format("%f", 0.5):match "[^05]+"
		if decpoint == "." then
			tolocale = function(str)
				return str
			end
		else
			tolocale = function(str)
				str = str:gsub("%.", decpoint, 1)
				return str
			end
		end
	end
	updatelocale()
	safe_tonumber = function(str)
		local num = tonumber(tolocale(str))
		if num then
			return num
		else
			updatelocale()
			return tonumber(tolocale(str))
		end
	end
end

return {
	case_insensitive = case_insensitive;
	no_rich_capture = no_rich_capture;
	read_hex = read_hex;
	safe_tonumber = safe_tonumber;
}
