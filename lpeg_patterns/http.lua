-- https://tools.ietf.org/html/rfc7230

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local uri = require "lpeg_patterns.uri"

local C = lpeg.C
local Cg = lpeg.Cg
local Cs = lpeg.Cs
local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local V = lpeg.V

-- RFC 7230 Section 3.2.3
local OWS = (core.SP + core.HTAB)^0
local RWS = (core.SP + core.HTAB)^1
local BWS = OWS

-- Analogue to RFC 7320 Section 7's ABNF extension of '#'
local function comma_sep(element, min, max)
	local sep = OWS * lpeg.P"," * OWS
	local extra = sep^1 * element
	local patt = element
	if min then
		for _=2, min do
			patt = patt * extra
		end
	else
		min = 0
	end
	if max then
		local more = max-min
		patt = patt * extra^-more
	else
		patt = patt * extra^0
	end
	if min == 0 then
		patt = patt^-1
	end
	patt = sep^0 * patt * sep^0 -- allow trailing or leading whitespace and commas
	return patt
end

-- RFC 7230 Section 2.7
local absolute_path = Cs((P"/" * uri.segment )^1)

-- RFC 7230 Section 3.2.6
local tchar = S "!#$%&'*+-.^_`|~" + core.DIGIT + core.ALPHA
local token = C(tchar^1)
local obs_text = R("\128\255")
local qdtext = core.HTAB + core.SP + P("\33") + R("\35\91", "\93\126") + obs_text
local quoted_pair = Cs(P"\\" * C(core.HTAB + core.SP + core.VCHAR + obs_text) / "%1")
local quoted_string = core.DQUOTE * Cs((qdtext + quoted_pair)^0) * core.DQUOTE

local ctext = core.HTAB + core.SP + R("\33\39", "\42\91", "\93\126") + obs_text
local comment = P { P"(" * ( ctext + quoted_pair + V(1) )^0 * P")" }

-- RFC 7230 Section 3.2
local field_name = token
local field_vchar = core.VCHAR + obs_text
local field_content = field_vchar * (( core.SP + core.HTAB )^1 * field_vchar)^-1
local obs_fold = core.CRLF * ( core.SP + core.HTAB )^1 / " "
local field_value = Cs(( field_content + obs_fold )^0)
local header_field = field_name * P":" * OWS * field_value * OWS

-- RFC 7230 Section 3.3.2
local Content_Length = core.DIGIT^1

-- RFC 7230 Section 4
local transfer_parameter = token * BWS * P"=" * BWS * ( token + quoted_string )
local transfer_extension = token * ( OWS * P";" * OWS * transfer_parameter )^0
local transfer_coding = transfer_extension

-- RFC 7230 Section 3.3.1
local Transfer_Encoding = comma_sep(transfer_coding, 1)

-- RFC 7230 Section 4.1.1
local chunk_ext_name = token
local chunk_ext_val = token + quoted_string
local chunk_ext = ( P";" * chunk_ext_name * ( P"=" * chunk_ext_val)^-1 )^0

-- RFC 7230 Section 4.3
local rank = (P"0" * (P"." * core.DIGIT^-3)^-1 + P"1" * ("." * (P"0")^-3)^-1) / tonumber
local t_ranking = OWS * P";" * OWS * P"q=" * rank
local t_codings = transfer_coding * Cg(t_ranking)^-1
local TE = comma_sep(t_codings)

-- RFC 7230 Section 4.4
local Trailer = comma_sep(field_name, 1)

-- RFC 7230 Section 5.3
local origin_form = absolute_path * (P"?" * uri.query)^-1
local absolute_form  = uri.absolute_uri
local authority_form = uri.authority
local asterisk_form  = P"*"
local request_target = origin_form + absolute_form + authority_form + asterisk_form

-- RFC 7230 Section 5.4
local Host = uri.host * (P":" * uri.port)^-1

-- RFC 7230 Section 6.7
local protocol_name = token
local protocol_version = token
local protocol = protocol_name * (P"/" * protocol_version)^-1
local Upgrade = comma_sep(protocol)

-- RFC 7230 Section 5.7.1
local received_protocol = (protocol_name * P"/")^-1 * protocol_version
local pseudonym = token
local received_by = uri.host * (P":" * uri.port)^-1 + pseudonym
local Via = comma_sep(received_protocol * RWS * received_by * (RWS * comment)^-1, 1)

-- RFC 7230 Section 6.1
local connection_option = token
local Connection = comma_sep(connection_option)

return {
	token = token;
	quoted_string = quoted_string;
	comment = comment;
	request_target = request_target;
	field_name = field_name;
	field_value = field_value;
	header_field = header_field;
	chunk_ext = chunk_ext;

	Connection = Connection;
	Content_Length = Content_Length;
	Host = Host;
	TE = TE;
	Trailer = Trailer;
	Transfer_Encoding = Transfer_Encoding;
	Upgrade = Upgrade;
	Via = Via;
}
