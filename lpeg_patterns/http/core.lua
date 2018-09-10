-- RFC 7230
-- Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing

local lpeg = require "lpeg"
local core = require "lpeg_patterns.core"
local uri = require "lpeg_patterns.uri"
local util = require "lpeg_patterns.util"

local C = lpeg.C
local Cc = lpeg.Cc
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Cs = lpeg.Cs
local Ct = lpeg.Ct
local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local V = lpeg.V

-- RFC 7230 Section 3.2.3
local OWS = (core.SP + core.HTAB)^0
local RWS = (core.SP + core.HTAB)^1
local BWS = OWS

-- Analogue to RFC 7230 Section 7's ABNF extension of '#'
-- Also documented as `#rule` under RFC 2616 Section 2.1
local sep = OWS * lpeg.P "," * OWS
local optional_sep = (lpeg.P"," + core.SP + core.HTAB)^0
local function comma_sep(element, min, max)
	local extra = sep * optional_sep * element
	local patt = element
	if min then
		for _=2, min do
			patt = patt * extra
		end
	else
		min = 0
		patt = patt^-1
	end
	if max then
		local more = max-min-1
		patt = patt * extra^-more
	else
		patt = patt * extra^0
	end
	return patt
end
-- allows leading + trailing
local function comma_sep_trim(...)
	return optional_sep * comma_sep(...) * optional_sep
end

-- RFC 7230 Section 2.6
local HTTP_name = P"HTTP"
local HTTP_version = HTTP_name * P"/" * (core.DIGIT * P"." * core.DIGIT / util.safe_tonumber)

-- RFC 7230 Section 2.7
local absolute_path = (P"/" * uri.segment )^1
local partial_uri = Ct(uri.relative_part * (P"?" * uri.query)^-1)

-- RFC 7230 Section 3.2.6
local tchar = S "!#$%&'*+-.^_`|~" + core.DIGIT + core.ALPHA
local token = C(tchar^1)
local obs_text = R("\128\255")
local qdtext = core.HTAB + core.SP + P"\33" + R("\35\91", "\93\126") + obs_text
local quoted_pair = Cs(P"\\" * C(core.HTAB + core.SP + core.VCHAR + obs_text) / "%1")
local quoted_string = core.DQUOTE * Cs((qdtext + quoted_pair)^0) * core.DQUOTE

local ctext = core.HTAB + core.SP + R("\33\39", "\42\91", "\93\126") + obs_text
local comment = P { P"(" * ( ctext + quoted_pair + V(1) )^0 * P")" }

-- RFC 7230 Section 3.2
local field_name = token / string.lower -- case insensitive
local field_vchar = core.VCHAR + obs_text
local field_content = field_vchar * (( core.SP + core.HTAB )^1 * field_vchar)^-1
local obs_fold = ( core.SP + core.HTAB )^0 * core.CRLF * ( core.SP + core.HTAB )^1 / " "
-- field_value is not correct, see Errata: https://www.rfc-editor.org/errata_search.php?rfc=7230&eid=4189
local field_value = Cs((field_content + obs_fold)^0)
local header_field = field_name * P":" * OWS * field_value * OWS

-- RFC 7230 Section 3.3.2
local Content_Length = core.DIGIT^1

-- RFC 7230 Section 4
-- See https://www.rfc-editor.org/errata_search.php?rfc=7230&eid=4683
local transfer_parameter = (token - S"qQ" * BWS * P"=") * BWS * P"=" * BWS * ( token + quoted_string )
local transfer_extension = Cf(Ct(token / string.lower) -- case insensitive
	* ( OWS * P";" * OWS * Cg(transfer_parameter) )^0, rawset)
local transfer_coding = transfer_extension

-- RFC 7230 Section 3.3.1
local Transfer_Encoding = comma_sep_trim(transfer_coding, 1)

-- RFC 7230 Section 4.1.1
local chunk_ext_name = token
local chunk_ext_val = token + quoted_string
-- See https://www.rfc-editor.org/errata_search.php?rfc=7230&eid=4667
local chunk_ext = ( P";" * chunk_ext_name * ( P"=" * chunk_ext_val)^-1 )^0

-- RFC 7230 Section 4.3
local rank = (P"0" * ((P"." * core.DIGIT^-3) / util.safe_tonumber + Cc(0)) + P"1" * ("." * (P"0")^-3)^-1) * Cc(1)
local t_ranking = OWS * P";" * OWS * S"qQ" * P"=" * rank -- q is case insensitive
local t_codings = (transfer_coding * t_ranking^-1) / function(t, q)
	if q then
		t["q"] = q
	end
	return t
end
local TE = comma_sep_trim(t_codings)

-- RFC 7230 Section 4.4
local Trailer = comma_sep_trim(field_name, 1)

-- RFC 7230 Section 5.3
local origin_form = Cs(absolute_path * (P"?" * uri.query)^-1)
local absolute_form = util.no_rich_capture(uri.absolute_uri)
local authority_form = util.no_rich_capture(uri.authority)
local asterisk_form = C"*"
local request_target = asterisk_form + origin_form + absolute_form + authority_form

-- RFC 7230 Section 3.1.1
local method = token
local request_line = method * core.SP * request_target * core.SP * HTTP_version * core.CRLF

-- RFC 7230 Section 5.4
local Host = uri.host * (P":" * uri.port)^-1

-- RFC 7230 Section 6.7
local protocol_name = token
local protocol_version = token
local protocol = protocol_name * (P"/" * protocol_version)^-1 / "%0"
local Upgrade = comma_sep_trim(protocol)

-- RFC 7230 Section 5.7.1
local received_protocol = (protocol_name * P"/" + Cc("HTTP")) * protocol_version / "%1/%2"
local pseudonym = token
-- workaround for https://lists.w3.org/Archives/Public/ietf-http-wg/2016OctDec/0527.html
local received_by = uri.host * ((P":" * uri.port) + -lpeg.B(",")) / "%0" + pseudonym
local Via = comma_sep_trim(Ct(
	Cg(received_protocol, "protocol")
	* RWS * Cg(received_by, "by")
	* (RWS * Cg(comment, "comment"))^-1
), 1)

-- RFC 7230 Section 6.1
local connection_option = token / string.lower -- case insensitive
local Connection = comma_sep_trim(connection_option)

return {
	comma_sep = comma_sep;
	comma_sep_trim = comma_sep_trim;

	OWS = OWS;
	RWS = RWS;
	BWS = BWS;

	chunk_ext = chunk_ext;
	comment = comment;
	field_name = field_name;
	field_value = field_value;
	header_field = header_field;
	method = method;
	obs_text = obs_text;
	partial_uri = partial_uri;
	pseudonym = pseudonym;
	qdtext = qdtext;
	quoted_string = quoted_string;
	rank = rank;
	request_line = request_line;
	request_target = request_target;
	t_ranking = t_ranking;
	tchar = tchar;
	token = token;

	Connection = Connection;
	Content_Length = Content_Length;
	Host = Host;
	TE = TE;
	Trailer = Trailer;
	Transfer_Encoding = Transfer_Encoding;
	Upgrade = Upgrade;
	Via = Via;
}
