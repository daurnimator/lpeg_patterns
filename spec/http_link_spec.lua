describe("lpeg_patterns.http.link", function()
	local http_link = require "lpeg_patterns.http.link"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a Link header", function()
		local Link = lpeg.Ct(http_link.Link) * EOF
		assert.same({{{host="example.com"}}}, Link:match"<//example.com>")
		assert.same({
			{
				{scheme = "http"; host = "example.com"; path = "/TheBook/chapter2";};
				rel = "previous";
				title="previous chapter"
			}},
			Link:match[[<http://example.com/TheBook/chapter2>; rel="previous"; title="previous chapter"]])
		assert.same({{{path = "/"}, rel = "http://example.net/foo"}},
			Link:match[[</>; rel="http://example.net/foo"]])
		assert.same({
				{{path = "/TheBook/chapter2"}, rel = "previous", title = "letztes Kapitel"};
				{{path = "/TheBook/chapter4"}, rel = "next", title = "nächstes Kapitel"};
			},
			Link:match[[</TheBook/chapter2>; rel="previous"; title*=UTF-8'de'letztes%20Kapitel, </TheBook/chapter4>; rel="next"; title*=UTF-8'de'n%c3%a4chstes%20Kapitel]])
		assert.same({{{scheme = "http"; host = "example.org"; path = "/"}, rel = "start http://example.net/relation/other"}},
			Link:match[[<http://example.org/>; rel="start http://example.net/relation/other"]])
	end)
end)
