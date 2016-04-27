local lpeg = require "lpeg"
local EOF = lpeg.P(-1)
describe("language tags", function()
	local Language_Tag = lpeg.Ct(require "lpeg_patterns.language".Language_Tag) * EOF
	it("parses examples from RFC 5646 Appendix A", function()
		-- Simple language subtag:
		assert.same({language = "de"; variant = {}; extension = {}}, Language_Tag:match "de") -- German
		assert.same({language = "fr"; variant = {}; extension = {}}, Language_Tag:match "fr") -- French
		assert.same({language = "ja"; variant = {}; extension = {}}, Language_Tag:match "ja") -- Japanese
		-- assert.same({language = "i-enochian"; variant = {}; extension = {}}, Language_Tag:match "i-enochian") -- example of a grandfathered tag
		-- Language subtag plus Script subtag:
		assert.same({language = "zh"; script = "Hant"; variant = {}; extension = {}}, Language_Tag:match "zh-Hant") -- Chinese written using the Traditional Chinese script
		assert.same({language = "zh"; script = "Hans"; variant = {}; extension = {}}, Language_Tag:match "zh-Hans") -- Chinese written using the Simplified Chinese script
		assert.same({language = "sr"; script = "Cyrl"; variant = {}; extension = {}}, Language_Tag:match "sr-Cyrl") -- Serbian written using the Cyrillic script
		assert.same({language = "sr"; script = "Latn"; variant = {}; extension = {}}, Language_Tag:match "sr-Latn") -- Serbian written using the Latin script
		-- Extended language subtags and their primary language subtag counterparts:
		assert.same({language = "zh"; extlang = "cmn", script = "Hans"; region = "CN"; variant = {}; extension = {}}, Language_Tag:match "zh-cmn-Hans-CN") -- Chinese, Mandarin, Simplified script, as used in China
		assert.same({language = "cmn"; script = "Hans"; region = "CN"; variant = {}; extension = {}}, Language_Tag:match "cmn-Hans-CN") -- Mandarin Chinese, Simplified script, as used in China
		assert.same({language = "zh"; extlang = "yue"; region = "HK"; variant = {}; extension = {}}, Language_Tag:match "zh-yue-HK") -- Chinese, Cantonese, as used in Hong Kong SAR
		assert.same({language = "yue"; region = "HK"; variant = {}; extension = {}}, Language_Tag:match "yue-HK") -- Cantonese Chinese, as used in Hong Kong SAR
		-- Language-Script-Region:
		assert.same({language = "zh"; script = "Hans"; region = "CN"; variant = {}; extension = {}}, Language_Tag:match "zh-Hans-CN") -- Chinese written using the Simplified script as used in mainland China
		assert.same({language = "sr"; script = "Latn"; region = "RS"; variant = {}; extension = {}}, Language_Tag:match "sr-Latn-RS") -- Serbian written using the Latin script as used in Serbia
		-- Language-Variant:
		assert.same({language = "sl"; variant = {"rozaj"}; extension = {}}, Language_Tag:match "sl-rozaj") -- Resian dialect of Slovenian
		assert.same({language = "sl"; variant = {"rozaj", "biske"}; extension = {}}, Language_Tag:match "sl-rozaj-biske") -- San Giorgio dialect of Resian dialect of Slovenian
		assert.same({language = "sl"; variant = {"nedis"}; extension = {}}, Language_Tag:match "sl-nedis") -- Nadiza dialect of Slovenian
		-- Language-Region-Variant:
		assert.same({language = "de"; region = "CH"; variant = {"1901"}; extension = {}}, Language_Tag:match "de-CH-1901") -- German as used in Switzerland using the 1901 variant [orthography]
		assert.same({language = "sl"; region = "IT"; variant = {"nedis"}; extension = {}}, Language_Tag:match "sl-IT-nedis") -- Slovenian as used in Italy, Nadiza dialect
		-- Language-Script-Region-Variant:
		assert.same({language = "hy"; script = "Latn"; region = "IT"; variant = {"arevela"}; extension = {}}, Language_Tag:match "hy-Latn-IT-arevela") -- Eastern Armenian written in Latin script, as used in Italy
		-- Language-Region:
		assert.same({language = "de"; region = "DE"; variant = {}; extension = {}}, Language_Tag:match "de-DE") -- German for Germany
		assert.same({language = "en"; region = "US"; variant = {}; extension = {}}, Language_Tag:match "en-US") -- English as used in the United States
		assert.same({language = "es"; region = "419"; variant = {}; extension = {}}, Language_Tag:match "es-419") -- Spanish appropriate for the Latin America and Caribbean region using the UN region code
		-- Private use subtags:
		assert.same({language = "de"; region = "CH"; privateuse = {"phonebk"}; variant = {}; extension = {}}, Language_Tag:match "de-CH-x-phonebk")
		assert.same({language = "az"; script = "Arab"; privateuse = {"AZE", "derbend"}; variant = {}; extension = {}}, Language_Tag:match "az-Arab-x-AZE-derbend")
		-- Private use registry values:
		assert.same({language = nil; privateuse = {"whatever"}; variant = {}; extension = {}}, Language_Tag:match "x-whatever") -- private use using the singleton 'x'
		assert.same({language = "qaa"; script = "Qaaa"; region = "QM"; privateuse = {"southern"}; variant = {}; extension = {}}, Language_Tag:match "qaa-Qaaa-QM-x-southern") -- all private tags
		assert.same({language = "de"; script = "Qaaa"; variant = {}; extension = {}}, Language_Tag:match "de-Qaaa") -- German, with a private script
		assert.same({language = "sr"; script = "Latn"; region = "QM"; variant = {}; extension = {}}, Language_Tag:match "sr-Latn-QM") -- Serbian, Latin script, private region
		assert.same({language = "sr"; script = "Qaaa"; region = "RS"; variant = {}; extension = {}}, Language_Tag:match "sr-Qaaa-RS") -- Serbian, private script, for Serbia
		-- Tags that use extensions (examples ONLY -- extensions MUST be defined by revision or update to this document, or by RFC):
		assert.same({language = "en"; region = "US"; variant = {}; extension = { u = {"islamcal"}}}, Language_Tag:match "en-US-u-islamcal")
		assert.same({language = "zh"; region = "CN"; variant = {}; extension = { a = {"myext"}}; privateuse = {"private"}}, Language_Tag:match "zh-CN-a-myext-x-private")
		assert.same({language = "en"; variant = {}; extension = { a = {"myext"}, b = {"another"}}}, Language_Tag:match "en-a-myext-b-another")
		-- Some Invalid Tags:
		assert.falsy(Language_Tag:match "de-419-DE") -- two region tags
		assert.falsy(Language_Tag:match "a-DE") -- use of a single-character subtag in primary position; note that there are a few grandfathered tags that start with "i-" that are valid
		-- assert.falsy(Language_Tag:match "ar-a-aaa-b-bbb-a-ccc") -- two extensions with same single-letter prefix
	end)
end)
