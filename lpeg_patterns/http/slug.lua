-- RFC 5023

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local http_core = require "lpeg_patterns.http.core"
local util = require "lpeg_patterns.util"

local Cs = lpeg.Cs
local P = lpeg.P
local R = lpeg.R

local slugtext = http_core.RWS / " "
	+ P"%" * (core.HEXDIG * core.HEXDIG / util.read_hex) / string.char
	+ R"\32\126"

local SLUG = Cs(slugtext^0)

return {
	SLUG = SLUG;
}
