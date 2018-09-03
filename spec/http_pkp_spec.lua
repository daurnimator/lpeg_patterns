describe("lpeg_patterns.http.pkp", function()
	local http_pkp = require "lpeg_patterns.http.pkp"
	local lpeg = require "lpeg"
	local EOF = lpeg.P(-1)
	it("Parses a HPKP header", function()
		-- Example from RFC 7469 2.1.5
		local pkp_patt = lpeg.Ct(http_pkp.Public_Key_Pins) * EOF
		assert.same({
			{
				sha256 = {
					"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
					"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
				};
			}, {
				["max-age"] = "3000";
			}
		}, pkp_patt:match([[max-age=3000; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))

		-- max-age is compulsory
		assert.same(nil, pkp_patt:match([[pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))
	end)
	it("Parses a HPKP Report header", function()
		-- Example from RFC 7469 2.1.5
		local pkp_patt = lpeg.Ct(http_pkp.Public_Key_Pins_Report_Only) * EOF
		assert.same({
			{
				sha256 = {
					"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
					"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
				};
			}, {
				["max-age"] = "3000";
			}
		}, pkp_patt:match([[max-age=3000; pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))
		-- max-age isn't compulsory
		assert.same({
			{
				sha256 = {
					"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=";
					"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=";
				};
			}, {
			}
		}, pkp_patt:match([[pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="]]))
	end)
end)
