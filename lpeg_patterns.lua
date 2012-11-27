local lpeg = require "lpeg"

d = function ( subject , pos , ... )
	io.stderr:write ( "DEBUG\t" , string.sub ( subject , pos ) , "\t" , ... )
	io.stderr:write ( "\n" )
end

local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local V = lpeg.V
local C = lpeg.C

local CHAR  = R"\0\127"
local SPACE = S"\40\32"
local CTL   = R"\0\31" + P"\127"

local specials = S[=[()<>@,;:\".[]]=]

local atom = (CHAR-specials-SPACE-CTL)^1
local dtext = CHAR - S"[]\\\13"
local qtext = CHAR - S'"\\\13'
local quoted_pair = "\\" * CHAR
local domain_literal = P"[" * ( dtext + quoted_pair )^0 + P"]"
local quoted_string = P'"' * ( qtext + quoted_pair )^0 * P'"'
local word = atom + quoted_string

local email do
	-- Implements an email "addr-spec" according to RFC822
	local domain_ref = atom
	local sub_domain = domain_ref + domain_literal
	local domain     = sub_domain * ( P"." * sub_domain )^0
	local local_part = word * ( P"." * word )^0
	local addr_spec  = local_part * P"@" * C(domain)

	email = addr_spec
end

local phone do
	local digit = R"09"
	local seperator = S"- ,."

	phone = P {
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

return {
	email = email ;
	phone = phone ;
}
