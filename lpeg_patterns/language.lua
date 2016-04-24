-- RFC 5646 Section 2.1

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"

local P = lpeg.P
local R = lpeg.R

local alphanum = core.ALPHA + core.DIGIT

local extlang = core.ALPHA * core.ALPHA * core.ALPHA
	* (P"-" * core.ALPHA * core.ALPHA * core.ALPHA)^2

local language = core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA^-3
	+ core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA
	+ core.ALPHA * core.ALPHA * core.ALPHA^-1 * (P"-" * extlang)^-1

local script = core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA

local region = core.ALPHA * core.ALPHA
	+ core.DIGIT * core.DIGIT * core.DIGIT

local variant = alphanum * alphanum * alphanum * alphanum *alphanum * alphanum^-3
	+ core.DIGIT * alphanum * alphanum * alphanum

local singleton = core.DIGIT + R("AW", "YZ", "aw", "yz")

local extension = singleton * (P"-" * (alphanum*alphanum*alphanum^-6))^1

local privateuse = P"x" * (P"-" * (alphanum*alphanum^-7))^1

local langtag = language
	* (P"-" * script)^-1
	* (P"-" * region)^-1
	* (P"-" * variant)^0
	* (P"-" * extension)^0
	* (P"-" * privateuse)^-1

local irregular = P"en-GB-oed"
	+ P"i-ami"
	+ P"i-bnn"
	+ P"i-default"
	+ P"i-enochian"
	+ P"i-hak"
	+ P"i-klingon"
	+ P"i-lux"
	+ P"i-mingo"
	+ P"i-navajo"
	+ P"i-pwn"
	+ P"i-tao"
	+ P"i-tay"
	+ P"i-tsu"
	+ P"sgn-BE-FR"
	+ P"sgn-BE-NL"
	+ P"sgn-CH-DE"

local regular = P"art-lojban"
	+ P"cel-gaulish"
	+ P"no-bok"
	+ P"no-nyn"
	+ P"zh-guoyu"
	+ P"zh-hakka"
	+ P"zh-min"
	+ P"zh-min-nan"
	+ P"zh-xiang"

local grandfathered = irregular + regular

local Language_Tag = langtag + privateuse + grandfathered

return {
	Language_Tag = Language_Tag;
}
