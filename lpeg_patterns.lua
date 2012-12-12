local tonumber = tonumber
local strchar  = string.char
local lpeg     = require "lpeg"

d = function ( subject , pos , ... )
	io.stderr:write ( "DEBUG\t" , string.sub ( subject , pos ) , "\t" , ... )
	io.stderr:write ( "\n" )
end
local _M = { }

local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local V = lpeg.V
local C = lpeg.C
local Cg = lpeg.Cg
local Cs = lpeg.Cs
local Ct = lpeg.Ct

-- Core Rules https://tools.ietf.org/html/rfc5234#appendix-B.1
local ALPHA = R("AZ","az")
local BIT   = S"01"
local CHAR  = R"\1\127"
local CRLF  = P"\r\n"
local CTL   = R"\0\31" + P"\127"
local DIGIT = R"09"
local HEXDIG= DIGIT + S"ABCDEFabcdef"
local VCHAR = R"\21\126"
local WSP   = S" \t"

do -- IPv4
	local dec_octet = (
			DIGIT
			+ R"19" * DIGIT
			+ P"1"  * DIGIT * DIGIT
			+ P"2"  * R"04" * DIGIT
			+ P"25" * R"05"
		) / tonumber
	_M.IPv4address = Cg ( dec_octet * P"." * dec_octet * P"." * dec_octet * P"." * dec_octet )
end

do -- IPv6
	-- RFC 3986 Section 3.2.2
	local h16 = HEXDIG * HEXDIG^-3 / function ( x ) return tonumber ( x , 16 ) end
	local ls32 = ( h16 * P":" * h16 ) + _M.IPv4address
	_M.IPv6address = Cg (              h16 * h16 * h16 * h16 * h16 * h16 * ls32
		+                            P"::" * h16 * h16 * h16 * h16 * h16 * ls32
		+ (                h16)^-1 * P"::" * h16 * h16 * h16 * h16       * ls32
		+ ((h16*P":")^-1 * h16)^-1 * P"::" * h16 * h16 * h16             * ls32
		+ ((h16*P":")^-2 * h16)^-1 * P"::" * h16 * h16                   * ls32
		+ ((h16*P":")^-3 * h16)^-1 * P"::" * h16                         * ls32
		+ ((h16*P":")^-4 * h16)^-1 * P"::"                               * ls32
		+ ((h16*P":")^-5 * h16)^-1 * P"::"                               * h16
		+ ((h16*P":")^-6 * h16)^-1 * P"::" )
end

do -- Email Addresses
	-- RFC 5322 Section 2.2.3

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

	_M.email_nocfws = addr_spec_text -- A variant that does not allow comments or folding whitespace
	_M.email = addr_spec
end

do -- URI
	-- RFC 3986

	local pct_encoded = P"%" * C ( HEXDIG * HEXDIG ) / function ( hex_num ) return strchar ( tonumber ( hex_num , "16" ) )  end -- 2.1
	local sub_delims  = S"!$&'()*+,;=" -- 2.2
	local unreserved  = ALPHA + DIGIT + S"-._~" -- 2.3

	local scheme      = C ( ALPHA * ( ALPHA + DIGIT + S"+-." )^0 ) -- 3.1

	local userinfo    = C ( ( unreserved + pct_encoded + sub_delims + P":" )^0 ) -- 3.2.1

	-- Host 3.2.2
	local IPvFuture   = C ( P"v" * HEXDIG^1 * P"." * ( unreserved + sub_delims + P":" )^1 )
	local IP_literal  = P"[" * ( _M.IPv6address + IPvFuture ) * P"]"
	local IP_host     = IP_literal + _M.IPv4address
	local host_char   = unreserved + pct_encoded --+ sub_delims
	local reg_name    = C ( host_char^0 )
	local host        = IP_host + reg_name
	-- Create a slightly more sane host pattern
	local hostsegment = (host_char-P".")^1
	local dns_entry   = C ( hostsegment * (P"."*hostsegment)^1 )
	local sane_host   = IP_host + dns_entry

	local port        = DIGIT^0 -- 3.2.3

	-- Path 3.3
	local pchar         = unreserved + pct_encoded + sub_delims + S":@"
	local path_abempty  = ( "/" * pchar^0 )^0
	local path_rootless = pchar^1 * path_abempty
	local path_absolute = P"/" * path_rootless^-1
	local path_noscheme = (pchar-P":")^1 * path_abempty

	local query = C ( ( pchar + S"/?" )^0 ) -- 3.4
	local fragment = query -- 3.5

	_M.uri = Ct (
		( Cg ( scheme , "scheme" ) * P"://" )^-1
		-- authority
			* ( Cg ( userinfo , "userinfo" ) * P"@" )^-1
			* Cg ( sane_host , "host" )
			* ( P":" * Cg ( port , "port" ) )^-1
		* Cg ( path_abempty , "path" )
		* ( P"?" * Cg ( query , "query" ) )^-1
		* ( P"#" * Cg ( fragment , "fragment" ) )^-1
	)
end

do -- Phone numbers
	local digit = R"09"
	local seperator = S"- ,."

	_M.phone = P {
		( V"International" + V"USA" ) * (seperator^-1 * V"extension" )^-1;

		extension = P"ext" * seperator^-1 * digit^1 ;

		International = P"+" * seperator^-1 * (
			P"1" * seperator^-1 * V"NANP" -- USA
			-- Other countries we haven't made specific patterns for yet
			+(P"20"+P"212"+P"213"+P"216"+P"218"+P"220"+P"221"
			+P"222"+P"223"+P"224"+P"225"+P"226"+P"227"+P"228"+P"229"
			+P"230"+P"231"+P"232"+P"233"+P"234"+P"235"+P"236"+P"237"
			+P"238"+P"239"+P"240"+P"241"+P"242"+P"243"+P"244"+P"245"
			+P"246"+P"247"+P"248"+P"249"+P"250"+P"251"+P"252"+P"253"
			+P"254"+P"255"+P"256"+P"257"+P"258"+P"260"+P"261"+P"262"
			+P"263"+P"264"+P"265"+P"266"+P"267"+P"268"+P"269"+P"27"
			+P"290"+P"291"+P"297"+P"298"+P"299"+P"30" +P"31" +P"32"
			+P"33" +P"34" +P"350"+P"351"+P"352"+P"353"+P"354"+P"355"
			+P"356"+P"357"+P"358"+P"359"+P"36" +P"370"+P"371"+P"372"
			+P"373"+P"374"+P"375"+P"376"+P"377"+P"378"+P"380"+P"381"
			+P"385"+P"386"+P"387"+P"389"+P"39" +P"40" +P"41" +P"420"
			+P"421"+P"423"+P"43" +P"44" +P"45" +P"46" +P"47" +P"48"
			+P"49" +P"500"+P"501"+P"502"+P"503"+P"504"+P"505"+P"506"
			+P"507"+P"508"+P"509"+P"51" +P"52" +P"53" +P"54" +P"55"
			+P"56" +P"57" +P"58" +P"590"+P"591"+P"592"+P"593"+P"594"
			+P"595"+P"596"+P"597"+P"598"+P"599"+P"60" +P"61" +P"62"
			+P"63" +P"64" +P"65" +P"66" +P"670"+P"672"+P"673"+P"674"
			+P"675"+P"676"+P"677"+P"678"+P"679"+P"680"+P"681"+P"682"
			+P"683"+P"684"+P"685"+P"686"+P"687"+P"688"+P"689"+P"690"
			+P"691"+P"692"+P"7"  +P"808"+P"81" +P"82" +P"84" +P"850"
			+P"852"+P"853"+P"855"+P"856"+P"86" +P"870"+P"871"+P"872"
			+P"873"+P"874"+P"878"+P"880"+P"881"+P"886"+P"90" +P"91"
			+P"92" +P"93" +P"94" +P"95" +P"960"+P"961"+P"962"+P"963"
			+P"964"+P"965"+P"966"+P"967"+P"968"+P"970"+P"971"+P"972"
			+P"973"+P"974"+P"975"+P"976"+P"977"+P"98" +P"992"+P"993"
			+P"994"+P"995"+P"996"+P"998" ) * (seperator^-1*digit)^6 -- At least 6 digits
		) ;

		USA = V"NANP" ;
		NANP = ( P"("^-1 * V"NPA" * P")"^-1 + V"NPA" ) * seperator^-1 * V"NXX" * seperator^-1 * V"USSubscriber" ;
		NPA = (digit-S"01")*digit*digit ;
		NXX = (digit-S"01")*digit*digit ;
		USSubscriber = digit*digit*digit*digit;
	}
end

return _M
