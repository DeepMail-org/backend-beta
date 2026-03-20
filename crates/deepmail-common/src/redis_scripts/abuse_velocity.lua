-- Sliding-window abuse velocity check.
-- KEYS[1]   counter key
-- ARGV[1]   now_ms
-- ARGV[2]   window_ms
-- ARGV[3]   threshold
-- Returns: {count, exceeded}

local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local threshold = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
redis.call('ZADD', key, now_ms, tostring(now_ms) .. ':' .. tostring(math.random(1000000)))
local count = redis.call('ZCARD', key)
redis.call('PEXPIRE', key, window_ms)

if count > threshold then
  return {count, 1}
end

return {count, 0}
