-- RFC 5987
-- Character Set and Language Encoding for
-- Hypertext Transfer Protocol (HTTP) Header Field Parameters

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local language = require "lpeg_patterns.language"
local util = require "lpeg_patterns.util"

local C = lpeg.C
local Cg = lpeg.Cg
local Cs = lpeg.Cs
local P = lpeg.P
local S = lpeg.S

local attr_char = core.ALPHA + core.DIGIT + S"!#$&+-.^_`|~"
-- can't use uri.pct_encoded, as it doesn't decode all characters
local pct_encoded = P"%" * (core.HEXDIG * core.HEXDIG / util.read_hex) / string.char
local value_chars = Cs((pct_encoded + attr_char)^0)
local parmname = C(attr_char^1)
-- ext-value uses charset from RFC 5987
local mime_charsetc = core.ALPHA + core.DIGIT + S"!#$%&+-^_`{}~"
local mime_charset = C(mime_charsetc^1)
local ext_value = Cg(mime_charset, "charset") * P"'" * Cg(language.Language_Tag, "language")^-1 * P"'" * value_chars

return {
	ext_value = ext_value;
	parmname = parmname;
}
