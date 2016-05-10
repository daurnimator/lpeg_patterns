-- RFC 5646 Section 2.1

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"

local C = lpeg.C
local P = lpeg.P
local R = lpeg.R
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct

local alphanum = core.ALPHA + core.DIGIT

local extlang = core.ALPHA * core.ALPHA * core.ALPHA * -#alphanum
	* (P"-" * core.ALPHA * core.ALPHA * core.ALPHA * -#alphanum)^-2

local language = Cg(core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA^-3, "language")
	+ Cg(core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA, "language")
	+ Cg(core.ALPHA * core.ALPHA * core.ALPHA^-1, "language") * (P"-" * Cg(extlang, "extlang"))^-1

local script = core.ALPHA * core.ALPHA * core.ALPHA * core.ALPHA * -#alphanum

local region = (
	core.ALPHA * core.ALPHA
	+ core.DIGIT * core.DIGIT * core.DIGIT
) * -#alphanum

local variant = core.DIGIT * alphanum * alphanum * alphanum
	+ alphanum * alphanum * alphanum * alphanum * alphanum * alphanum^-3

local singleton = core.DIGIT + R("AW", "YZ", "aw", "yz")

local extension = C(singleton) * Ct((P"-" * (alphanum*alphanum*alphanum^-6 / string.lower))^1)

local privateuse = P"x" * Ct((P"-" * C(alphanum*alphanum^-7))^1)

local langtag = language
	* (P"-" * Cg(script, "script"))^-1
	* (P"-" * Cg(region, "region"))^-1
	* Cg(Ct((P"-" * C(variant))^0), "variant")
	* Cg(Cf(Ct(true)*(P"-" * Cg(extension))^0, rawset), "extension")
	* (P"-" * Cg(privateuse, "privateuse"))^-1

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

local regular = P"art" * P"-" * P"lojban"
	+ P"cel" * P"-" * P"gaulish"
	+ P"no" * P"-" * P"bok"
	+ P"no" * P"-" * P"nyn"
	+ P"zh" * P"-" * P"guoyu"
	+ P"zh" * P"-" * P"hakka"
	+ P"zh" * P"-" * P"min"
	+ P"zh" * P"-" * P"min" * P"-" * P"nan"
	+ P"zh" * P"-" * P"xiang"

local grandfathered = irregular + regular

local Language_Tag = langtag
	+ Cg(privateuse, "privateuse") * Cg(Ct(true), "variant") * Cg(Ct(true), "extension")
	+ grandfathered

return {
	Language_Tag = Language_Tag;
}