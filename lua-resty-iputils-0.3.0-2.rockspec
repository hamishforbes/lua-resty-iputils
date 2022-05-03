package = "lua-resty-iputils"
version = "0.3.0-2"

source = {
  url = "git+https://github.com/hamishforbes/lua-resty-iputils.git",
  tag = "v0.3.0",
}

description = {
  summary = "Utility functions for working with IP addresses in Openresty",
  license = "MIT",
}

dependencies = {
  "lua >= 5.1",
}

build = {
  type = "builtin",
  modules = {
    ["resty.iputils"] = "lib/resty/iputils.lua",
  },
}
