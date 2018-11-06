local ipairs, tonumber, tostring, type = ipairs, tonumber, tostring, type
local bit        = require("bit")
local lshift     = bit.lshift
local band       = bit.band
local bor        = bit.bor
local xor        = bit.bxor
local byte       = string.byte
local str_find   = string.find
local str_sub    = string.sub

local lrucache = nil

local _M = {
    _VERSION = '0.3.0',
}

local mt = { __index = _M }

local ffi = require("ffi")
ffi.cdef[[
typedef struct {
  int     version;
  uint8_t addr[16];
  uint8_t mask[16];
  int     proto;
} CIDR;
CIDR *cidr_from_str(const char *);
char *cidr_to_str(const CIDR *, int);
int cidr_contains(const CIDR *, const CIDR *);
void cidr_free(CIDR *);
void free(void *);
]]

local cidr = ffi.load("cidr")

local errs = {
  EINVAL = 22,
  ENOENT = 2,
  ENOMEM = 12,
  EFAULT = 14,
  EPROTO = 71,
}

-- Precompute binary subnet masks...
local bin_masks = {}
for i=0,32 do
    bin_masks[tostring(i)] = lshift((2^i)-1, 32-i)
end
-- ... and their inverted counterparts
local bin_inverted_masks = {}
for i=0,32 do
    local i = tostring(i)
    bin_inverted_masks[i] = xor(bin_masks[i], bin_masks["32"])
end

local log_err
if ngx then
    log_err = function(...)
        ngx.log(ngx.ERR, ...)
    end
else
    log_err = function(...)
        print(...)
    end
end


local function enable_lrucache(size)
    local size = size or 4000  -- Cache the last 4000 IPs (~1MB memory) by default
    local lrucache_obj, err = require("resty.lrucache").new(size)
    if not lrucache_obj then
        return nil, "failed to create the cache: " .. (err or "unknown")
    end
    lrucache = lrucache_obj
    return true
end
_M.enable_lrucache = enable_lrucache


local function split_octets(input)
    local pos = 0
    local prev = 0
    local octs = {}

    for i=1, 4 do
        pos = str_find(input, ".", prev, true)
        if pos then
            if i == 4 then
                -- Should not have a match after 4 octets
                return nil, "Invalid IP"
            end
            octs[i] = str_sub(input, prev, pos-1)
        elseif i == 4 then
            -- Last octet, get everything to the end
            octs[i] = str_sub(input, prev, -1)
            break
        else
            return nil, "Invalid IP"
        end
        prev = pos +1
    end

    return octs
end


local function unsign(bin)
    if bin < 0 then
        return 4294967296 + bin
    end
    return bin
end


local function ip2bin(ip)
    if lrucache then
        local get = lrucache:get(ip)
        if get then
            return get[1], get[2]
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
        local bin_octet = tonumber(octet)
        if not bin_octet or bin_octet < 0 or bin_octet > 255 then
            return nil, "Invalid octet: "..tostring(octet)
        end
        bin_octets[i] = bin_octet
        bin_ip = bor(lshift(bin_octet, 8*(4-i) ), bin_ip)
    end

    bin_ip = unsign(bin_ip)
    if lrucache then
        lrucache:set(ip, {bin_ip, bin_octets})
    end
    return bin_ip, bin_octets
end
_M.ip2bin = ip2bin


local function split_cidr(input)
    local pos = str_find(input, "/", 0, true)
    if not pos then
        return {input}
    end
    return {str_sub(input, 1, pos-1), str_sub(input, pos+1, -1)}
end


local function parse_cidr(cidr)
    local mask_split = split_cidr(cidr, '/')
    local net        = mask_split[1]
    local mask       = mask_split[2] or "32"
    local mask_num   = tonumber(mask)

    if not mask_num or (mask_num > 32 or mask_num < 0) then
        return nil, "Invalid prefix: /"..tostring(mask)
    end

    local bin_net, err = ip2bin(net) -- Convert IP to binary
    if not bin_net then
        return nil, err
    end
    local bin_mask     = bin_masks[mask] -- Get masks
    local bin_inv_mask = bin_inverted_masks[mask]

    local lower = band(bin_net, bin_mask) -- Network address
    local upper = bor(lower, bin_inv_mask) -- Broadcast address
    return unsign(lower), unsign(upper)
end
_M.parse_cidr = parse_cidr


local function parse_cidrs(cidrs)
    local out = {}
    local i = 1
    for _,cidr in ipairs(cidrs) do
        local lower, upper = parse_cidr(cidr)
        if not lower then
            log_err("Error parsing '", cidr, "': ", upper)
        else
            out[i] = {lower, upper}
            i = i+1
        end
    end
    return out
end
_M.parse_cidrs = parse_cidrs



local function from_str(string)
  local result = cidr.cidr_from_str(string)
  if result == nil then
    local errno = ffi.errno()
    if errno == errs.EFAULT then
      return nil, "Passed NULL"
    elseif errno == errs.EINVAL then
      return nil, "Can't parse the input string"
    elseif errno == errs.ENOENT then
      return nil, "Internal error"
    end
  end

  result = ffi.gc(result, cidr.cidr_free)

  return result
end

local function to_str(struct)
  if type(struct) ~= "cdata" then
    return nil, "Invalid argument (bad block or flags)"
  end

  local result = cidr.cidr_to_str(struct, 0)
  if result == nil then
    local errno = ffi.errno()
    if errno == errs.EINVAL then
      return nil, "Invalid argument (bad block or flags)"
    elseif errno == errs.ENOENT then
      return nil, "Internal error"
    elseif errno == errs.ENOMEM then
      return nil, "malloc() failed"
    end
  end

  local string = ffi.string(result)
  ffi.C.free(result)

  return string
end

local function contains(big, little)
  if big == nil or little == nil then
    return nil, "Passed NULL"
  elseif type(big) ~= "cdata" or type(little) ~= "cdata" then
    return nil, "Invalid argument"
  end

  local result = cidr.cidr_contains(big, little)
  if result == 0 then
    return true
  else
    local errno = ffi.errno()
    if errno == errs.EFAULT then
      return nil, "Passed NULL"
    elseif errno == errs.EINVAL then
      return nil, "Invalid argument"
    elseif errno == errs.ENOENT then
      return nil, "Internal error"
    elseif errno == errs.EPROTO then
      return nil, "Protocols don't match"
    end

    return false
  end
end


local function parse_cidrs_ipv6(cidrs)
    local out = {}
    local i = 1
    for _, cidr in ipairs(cidrs) do
        local struct, err = from_str(cidr)
        if not struct then
            log_err("Error parsing '", cidr, "': ", err)
        else
            out[i] = struct
            i = i+1
        end
    end
    return out
end

_M.parse_cidrs_ipv6 = parse_cidrs_ipv6

local function ip_in_cidrs_ipv6(ip, cidrs)
    local struct, err = from_str(ip)
    if not struct then
        log_err("Error parsing '", ip, "': ", err)
        return false
    end

    for _, cidr in ipairs(cidrs) do
       if contains(cidr, struct) then
           return true
       end 
    end
    return false
end

_M.ip_in_cidrs_ipv6 = ip_in_cidrs_ipv6

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


local function binip_in_cidrs(bin_ip_ngx, cidrs)
    if 4 ~= #bin_ip_ngx then
        return false, "invalid IP address"
    end

    local bin_ip = 0
    for i=1,4 do
        bin_ip = bor(lshift(bin_ip, 8), byte(bin_ip_ngx, i))
    end
    bin_ip = unsign(bin_ip)

    for _,cidr in ipairs(cidrs) do
        if bin_ip >= cidr[1] and bin_ip <= cidr[2] then
            return true
        end
    end
    return false
end
_M.binip_in_cidrs = binip_in_cidrs

return _M
