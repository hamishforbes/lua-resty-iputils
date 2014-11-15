local ipairs, unpack, tonumber, tostring, type = ipairs, unpack, tonumber, tostring, type
local ngx        = ngx
local ngx_log    = ngx.log
local ngx_ERR    = ngx.ERR
local bit        = require("bit")
local tobit      = bit.tobit
local lshift     = bit.lshift
local band       = bit.band
local bor        = bit.bor
local xor        = bit.bxor
local match     = string.match

local resty_lrucache = require "resty.lrucache"
local lrucache = nil

local _M = {
    _VERSION = '0.01',
}

local mt = { __index = _M }


-- Precompute binary subnet masks...
local bin_masks = {}
for i=1,32 do
    bin_masks[tostring(i)] = lshift(tobit((2^i)-1), 32-i)
end
-- ... and their inverted counterparts
local bin_inverted_masks = {}
for i=1,32 do
    local i = tostring(i)
    bin_inverted_masks[i] = xor(bin_masks[i], bin_masks["32"])
end


local function enable_lrucache(size)
    local size = size or 4000  -- Cache the last 4000 IPs (~1MB memory) by default
    local lrucache_obj, err = resty_lrucache.new(4000)
    if not lrucache_obj then
        return nil, "failed to create the cache: " .. (err or "unknown")
    end
    lrucache = lrucache_obj
    return true
end
_M.enable_lrucache = enable_lrucache


local function split_octets(input)
    local oct1, oct2, oct3, oct4 = match(input, "(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if not oct1 then
        return nil
    end
    return {oct1, oct2, oct3, oct4}
end


local function ip2bin(ip)
    if lrucache then
        local get = lrucache:get(ip)
        if get then
            return unpack(get)
        end
    end

    if type(ip) ~= "string" then
        return nil, "IP must be a string"
    end

    local octets = split_octets(ip)
    if not octets or #octets ~= 4 then
        return nil, "Invalid IP"
    end

    -- Return the binary representation of an IP and a table of binary octets
    local bin_octets = {}
    local bin_ip = 0

    for i,octet in ipairs(octets) do
        local bin_octet = tobit(tonumber(octet))
        if bin_octet > 255 then
            return nil, "Octet out of range: "..tostring(octet)
        end
        bin_octets[i] = bin_octet
        bin_ip = bor(lshift(bin_octet, 8*(4-i) ), bin_ip)
    end
    if lrucache then
        lrucache:set(ip, {bin_ip, bin_octets})
    end
    return bin_ip, bin_octets
end
_M.ip2bin = ip2bin


local function split_cidr(input)
    local net, mask = match(input, "(.+)/(%d+)")
    if not net then
        return {input}
    end
    return {net, mask}
end


local function parse_cidr(cidr)
    local mask_split = split_cidr(cidr, '/')
    local net        = mask_split[1]
    local mask       = mask_split[2] or "32"
    local mask_num = tonumber(mask)
    if mask_num > 32 or mask_num < 1 then
        return nil, "Invalid prefix: /"..mask
    end

    local bin_net, err = ip2bin(net) -- Convert IP to binary
    if not bin_net then
        return nil, err
    end
    local bin_mask     = bin_masks[mask] -- Get masks
    local bin_inv_mask = bin_inverted_masks[mask]

    local lower = band(bin_net, bin_mask) -- Network address
    local upper = bor(lower, bin_inv_mask) -- Broadcast address
    return lower, upper
end
_M.parse_cidr = parse_cidr


local function parse_cidrs(cidrs)
    local out = {}
    local i = 1
    for _,cidr in ipairs(cidrs) do
        local lower, upper = parse_cidr(cidr)
        if not lower then
            ngx_log(ngx_ERR, "Error parsing '", cidr, "': ", upper)
        else
            out[i] = {lower, upper}
            i = i+1
        end
    end
    return out
end
_M.parse_cidrs = parse_cidrs


local function ip_in_cidrs(ip, cidrs)
    local bin_ip, bin_octets = ip2bin(ip)
    if not bin_ip then
        return nil, bin_octets
    end

    for _,cidr in ipairs(cidrs) do
        if bin_ip >= cidr[1] and bin_ip <= cidr[2] then
            return true
        end
    end
    return false
end
_M.ip_in_cidrs = ip_in_cidrs


return _M
