local lpeg = require "lpeg"
local EOF = lpeg.P(-1)
describe("language tags", function()
	local language = require "lpeg_patterns.language"
	local langtag = lpeg.Ct(language.langtag) * EOF
	local Language_Tag = language.Language_Tag * EOF
	describe("examples from RFC 5646 Appendix A", function()
		it("Parses Simple language subtag", function()
			assert.same({language = "de"}, langtag:match "de") -- German
			assert.same({language = "fr"}, langtag:match "fr") -- French
			assert.same({language = "ja"}, langtag:match "ja") -- Japanese
			assert.truthy(Language_Tag:match "i-enochian") -- example of a grandfathered tag
		end)
		it("Parses Language subtag plus Script subtag", function()
			assert.same({language = "zh"; script = "Hant"}, langtag:match "zh-Hant") -- Chinese written using the Traditional Chinese script
			assert.same({language = "zh"; script = "Hans"}, langtag:match "zh-Hans") -- Chinese written using the Simplified Chinese script
			assert.same({language = "sr"; script = "Cyrl"}, langtag:match "sr-Cyrl") -- Serbian written using the Cyrillic script
			assert.same({language = "sr"; script = "Latn"}, langtag:match "sr-Latn") -- Serbian written using the Latin script
		end)
		it("Parses Extended language subtags and their primary language subtag counterparts", function()
			assert.same({language = "zh"; extlang = "cmn", script = "Hans"; region = "CN"}, langtag:match "zh-cmn-Hans-CN") -- Chinese, Mandarin, Simplified script, as used in China
			assert.same({language = "cmn"; script = "Hans"; region = "CN"}, langtag:match "cmn-Hans-CN") -- Mandarin Chinese, Simplified script, as used in China
			assert.same({language = "zh"; extlang = "yue"; region = "HK"}, langtag:match "zh-yue-HK") -- Chinese, Cantonese, as used in Hong Kong SAR
			assert.same({language = "yue"; region = "HK"}, langtag:match "yue-HK") -- Cantonese Chinese, as used in Hong Kong SAR
		end)
		it("Parses Language-Script-Region", function()
			assert.same({language = "zh"; script = "Hans"; region = "CN"}, langtag:match "zh-Hans-CN") -- Chinese written using the Simplified script as used in mainland China
			assert.same({language = "sr"; script = "Latn"; region = "RS"}, langtag:match "sr-Latn-RS") -- Serbian written using the Latin script as used in Serbia
		end)
		it("Parses Language-Variant", function()
			assert.same({language = "sl"; variant = {"rozaj"}}, langtag:match "sl-rozaj") -- Resian dialect of Slovenian
			assert.same({language = "sl"; variant = {"rozaj", "biske"}}, langtag:match "sl-rozaj-biske") -- San Giorgio dialect of Resian dialect of Slovenian
			assert.same({language = "sl"; variant = {"nedis"}}, langtag:match "sl-nedis") -- Nadiza dialect of Slovenian
		end)
		it("Parses Language-Region-Variant", function()
			assert.same({language = "de"; region = "CH"; variant = {"1901"}}, langtag:match "de-CH-1901") -- German as used in Switzerland using the 1901 variant [orthography]
			assert.same({language = "sl"; region = "IT"; variant = {"nedis"}}, langtag:match "sl-IT-nedis") -- Slovenian as used in Italy, Nadiza dialect
		end)
		it("Parses Language-Script-Region-Variant", function()
			assert.same({language = "hy"; script = "Latn"; region = "IT"; variant = {"arevela"}}, langtag:match "hy-Latn-IT-arevela") -- Eastern Armenian written in Latin script, as used in Italy
		end)
		it("Parses Language-Region", function()
			assert.same({language = "de"; region = "DE"}, langtag:match "de-DE") -- German for Germany
			assert.same({language = "en"; region = "US"}, langtag:match "en-US") -- English as used in the United States
			assert.same({language = "es"; region = "419"}, langtag:match "es-419") -- Spanish appropriate for the Latin America and Caribbean region using the UN region code
		end)
		it("Parses private use subtags", function()
			assert.same({language = "de"; region = "CH"; privateuse = {"phonebk"}}, langtag:match "de-CH-x-phonebk")
			assert.same({language = "az"; script = "Arab"; privateuse = {"AZE", "derbend"}}, langtag:match "az-Arab-x-AZE-derbend")
		end)
		it("Parses private use registry values", function()
			assert.truthy(Language_Tag:match "x-whatever") -- private use using the singleton 'x'
			assert.same({language = "qaa"; script = "Qaaa"; region = "QM"; privateuse = {"southern"}}, langtag:match "qaa-Qaaa-QM-x-southern") -- all private tags
			assert.same({language = "de"; script = "Qaaa"}, langtag:match "de-Qaaa") -- German, with a private script
			assert.same({language = "sr"; script = "Latn"; region = "QM"}, langtag:match "sr-Latn-QM") -- Serbian, Latin script, private region
			assert.same({language = "sr"; script = "Qaaa"; region = "RS"}, langtag:match "sr-Qaaa-RS") -- Serbian, private script, for Serbia
		end)
		it("Parses tags that use extensions", function()
			assert.same({language = "en"; region = "US"; extension = { u = {"islamcal"}}}, langtag:match "en-US-u-islamcal")
			assert.same({language = "zh"; region = "CN"; extension = { a = {"myext"}}; privateuse = {"private"}}, langtag:match "zh-CN-a-myext-x-private")
			assert.same({language = "en"; extension = { a = {"myext"}, b = {"another"}}}, langtag:match "en-a-myext-b-another")
		end)
		it("Rejects Invalid Tags", function()
			assert.falsy(langtag:match "de-419-DE") -- two region tags
			assert.falsy(langtag:match "a-DE") -- use of a single-character subtag in primary position; note that there are a few grandfathered tags that start with "i-" that are valid
			assert.falsy(langtag:match "ar-a-aaa-b-bbb-a-ccc") -- two extensions with same single-letter prefix
		end)
	end)
	it("captures whole text when using Language_Tag", function()
		assert.same("en", Language_Tag:match "en")
		assert.same("hy-Latn-IT-arevela", Language_Tag:match "hy-Latn-IT-arevela")
	end)
end)
