-- KEYS[1] = bucket key
-- ARGV[1] = now_ms
-- ARGV[2] = capacity
-- ARGV[3] = refill_per_sec
-- ARGV[4] = requested_tokens

local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill_per_sec = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

local state = redis.call("HMGET", key, "tokens", "last_ms")
local tokens = tonumber(state[1])
local last_ms = tonumber(state[2])

if tokens == nil then
  tokens = capacity
  last_ms = now_ms
end

local elapsed_ms = math.max(0, now_ms - last_ms)
local refill_tokens = (elapsed_ms / 1000.0) * refill_per_sec
tokens = math.min(capacity, tokens + refill_tokens)

local allowed = 0
local retry_after_ms = 0

if tokens >= requested then
  tokens = tokens - requested
  allowed = 1
else
  local missing = requested - tokens
  retry_after_ms = math.ceil((missing / refill_per_sec) * 1000)
end

redis.call("HSET", key, "tokens", tokens, "last_ms", now_ms)
redis.call("PEXPIRE", key, 120000)

return { allowed, string.format("%.6f", tokens), retry_after_ms }
