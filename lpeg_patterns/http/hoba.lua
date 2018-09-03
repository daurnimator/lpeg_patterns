-- RFC 7486
-- HTTP Origin-Bound Authentication (HOBA)

local lpeg = require "lpeg"

local C = lpeg.C

local Hobareg = C"regok" + C"reginwork"

return {
	Hobareg = Hobareg;
}
