local redis_host, redis_port, redis_db = '127.0.0.1', 6379, 0
local ban_interval = 100     -- the interval per time slice for per client ip in seconds
local ban_threshold = 100    -- the number of requests within ban_interval that will be banned if current client ip exceeds.
local ban_banned_time = 300  -- the initial banned time for per banned client ip in seconds
local ban_banned_max = 43200  -- the max banned time for per banned client ip in seconds
local recaptcha_upstream = 'http://127.0.0.1:7777/'

-- init redis
local redis = require 'resty.redis'
local r = redis.new()
r:set_timeout(1000)

local ok, err = r.connect(r, redis_host, redis_port)
if not ok then
  goto end_anti_spider
end

r:select(redis_db)

client_ip = ngx.var.remote_addr

is_white, err = r:sismember('ngx:banned:white_list', client_ip)
if is_white == 1 then
  goto end_anti_spider
end

is_black, err = r:sismember('ngx:banned:black_list', client_ip)
if is_black == 1 then
  ngx.exit(ngx.HTTP_FORBIDDEN)
  goto end_anti_spider
end

-- increase request count in current time slice
res, err = r:incr('ngx:client:ip:' .. client_ip .. ':count')
client_req_count = tonumber(res)

-- a fresh time slice.
if client_req_count == 1 then
  res, err = r:expire('ngx:client:ip:' .. client_ip .. ':count', ban_interval)
  goto end_anti_spider
-- beyond the ban_threshold, then increase banned time and redirect to recaptcha page.
elseif client_req_count > ban_threshold then
  -- increase banned time
  ttl, err = r:ttl('ngx:client:ip:' .. client_ip .. ':count')
  if tonumber(ttl) + ban_banned_time < ban_banned_max then
    res, err = r:expire('ngx:client:ip:' .. client_ip .. ':count', tonumber(ttl) + ban_banned_time)
  end
  local source = ngx.encode_base64(ngx.var.scheme .. '://' .. ngx.var.host .. ':' .. ngx.var.server_port .. ngx.var.request_uri)
  local dest = recaptcha_upstream .. '?continue=' .. source
  ngx.redirect(dest, 302)
end

::end_anti_spider::
local ok, err = r:close()
