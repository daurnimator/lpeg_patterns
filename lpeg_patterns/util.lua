local function read_hex(hex_num)
	return tonumber(hex_num, 16)
end

return {
	read_hex = read_hex;
}
