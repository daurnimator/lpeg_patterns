-- This is a private module containing utility functions shared by various http parsers

local lpeg = require "lpeg"
local http_core = require "lpeg_patterns.http.core"

local P = lpeg.P
local Cc = lpeg.Cc
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local Cmt = lpeg.Cmt

local directive_name = http_core.token / string.lower
local directive_value = http_core.token + http_core.quoted_string
local directive = Cg(directive_name * ((http_core.OWS * P"=" * http_core.OWS * directive_value) + Cc(true)))

-- Helper function that doesn't match if there are duplicate keys
local function no_dup_cmt(s, i, t, name, value, ...)
	local old = t[name]
	if old then
		return false
	end
	t[name] = value
	if ... then
		return no_dup_cmt(s, i, t, ...)
	elseif t["max-age"] then -- max-age is required
		return true, t
	end
	-- else return nil
end

local function no_dup(patt)
	return Cmt(Ct(true) * patt, no_dup_cmt)
end

return {
	directive = directive;
	no_dup = no_dup;
}
