-- Email Addresses
-- RFC 5322 Section 2.2.3

local lpeg = require "lpeg"
local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local V = lpeg.V
local C = lpeg.C
local Cs = lpeg.Cs

local core = require "lpeg_patterns.core"
local CHAR = core.CHAR
local CRLF = core.CRLF
local CTL = core.CTL
local WSP = core.WSP
local VCHAR = core.VCHAR

local quoted_pair = Cs ( "\\" * C(VCHAR + WSP) / function(...) return ... end )

-- Folding White Space
local FWS = Cs ( (WSP^0 * CRLF)^-1 * WSP^1 / " " ) -- Fold whitespace into a single " "

-- Comments
local ctext   = R"\33\39" + R"\42\91" + R"\93\126"
local comment = P {
	V"comment" ;
	ccontent = ctext + quoted_pair + V"comment" ;
	comment  = P"("* C ( (FWS^-1*V"ccontent")^0 ) * FWS^-1 * P")" ;
}
local CFWS = ((FWS^-1 * comment)^1 * FWS^-1 + FWS ) / function() end

-- Atom
local specials      = S[=[()<>@,;:\".[]]=]
local atext         = CHAR-specials-P" "-CTL
local atom          = CFWS^-1 * C(atext^1) * CFWS^-1
local dot_atom_text = atext^1 * ( P"." * atext^1 )^0
local dot_atom      = CFWS^-1 * C(dot_atom_text) * CFWS^-1

-- Quoted Strings
local qtext              = S"\33"+R("\35\91","\93\126")
local qcontent           = qtext + quoted_pair
local quoted_string_text = P'"' * Cs((FWS^-1 * qcontent)^0) * FWS^-1 * P'"'
local quoted_string      = CFWS^-1 * quoted_string_text * CFWS^-1

-- Addr-spec
local dtext               = R("\33\90","\94\126")
local domain_literal_text = P"[" * C((FWS^-1 * dtext)^0) * FWS^-1 * P"]"

local domain_text     = dot_atom_text + domain_literal_text
local local_part_text = dot_atom_text + quoted_string_text
local addr_spec_text  = local_part_text * P"@" * local_part_text

local domain_literal = CFWS^-1 * domain_literal_text * CFWS^-1
local domain         = dot_atom + domain_literal
local local_part     = dot_atom + quoted_string
local addr_spec      = local_part * P"@" * domain

return {
	email = addr_spec;

	-- A variant that does not allow comments or folding whitespace
	email_nocfws = addr_spec_text;
}
