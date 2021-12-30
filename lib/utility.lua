local utility = {}

local math = require "math"
local time = require "posix.time"

utility.bit = nil

utility.loglevel = {
    TRACE = {
        level = 6,
        name = "TRACE"
    },
    DEBUG = {
        level = 5,
        name = "DEBUG"
    },
    INFO = {
        level = 4,
        name = "INFO"
    },
    WARN = {
        level = 3,
        name = "WARN"
    },
    ERROR = {
        level = 2,
        name = "ERROR"
    },
    FATAL = {
        level = 1,
        name = "FATAL"
    }
}

-- Found this clever function here: https://stackoverflow.com/a/15434737
-- This function will assist in compatibility given differences between OpenWrt, Turris OS, etc.
function utility.is_module_available(name)
    if package.loaded[name] then
        return true
    else
        for _, searcher in ipairs(package.searchers or package.loaders) do
            local loader = searcher(name)
            if type(loader) == 'function' then
                package.preload[name] = loader
                return true
            end
        end
        return false
    end
end

function utility.get_config_setting(config_file_name, config_section, setting_name)
    config_file_name = config_file_name or "sqm-autorate" -- Default to sqm-autorate if not provided

    local uci_lib = nil
    local settings = nil
    if utility.is_module_available("luci.model.uci") then
        uci_lib = require("luci.model.uci")
        settings = uci_lib.cursor()
    end

    local value = settings:get(config_file_name, "@" .. config_section, setting_name)
    if value then
        return value
    end

    return nil
end

function utility.get_config_setting_as_num(config_file_name, config_section, setting_name)
    local value = utility.get_config_setting(config_file_name, config_section, setting_name)
    if value then
        return tonumber(value, 10)
    end
    return nil
end

utility.use_loglevel = utility.loglevel[string.upper(
    utility.get_config_setting("sqm-autorate", "output[0]", "log_level") or "INFO")]

-- Basic homegrown logger to keep us from having to import yet another module
function utility.logger(loglevel, message)
    if (loglevel.level <= utility.use_loglevel.level) then
        local cur_date = os.date("%Y%m%dT%H:%M:%S")
        local out_str = string.format("[%s - %s]: %s", loglevel.name, cur_date, message)
        print(out_str)
    end
end

function utility.a_else_b(a, b)
    if a then
        return a
    else
        return b
    end
end

function utility.nsleep(s, ns)
    -- nanosleep requires integers
    time.nanosleep({
        tv_sec = math.floor(s),
        tv_nsec = math.floor(((s % 1.0) * 1e9) + ns)
    })
end

function utility.get_current_time()
    local time_s, time_ns = 0, 0
    local val1, val2 = time.clock_gettime(time.CLOCK_REALTIME)
    if type(val1) == "table" then
        time_s = val1.tv_sec
        time_ns = val1.tv_nsec
    else
        time_s = val1
        time_ns = val2
    end
    return time_s, time_ns
end

function utility.get_time_after_midnight_ms()
    local time_s, time_ns = utility.get_current_time()
    return (time_s % 86400 * 1000) + (math.floor(time_ns / 1000000))
end

if utility.is_module_available("bit") then
    utility.bit = require "bit"
elseif utility.is_module_available("bit32") then
    utility.bit = require "bit32"
end

function utility.calculate_checksum(data)
    local checksum = 0
    for i = 1, #data - 1, 2 do
        checksum = checksum + (utility.bit.lshift(string.byte(data, i), 8)) + string.byte(data, i + 1)
    end
    if utility.bit.rshift(checksum, 16) then
        checksum = utility.bit.band(checksum, 0xffff) + utility.bit.rshift(checksum, 16)
    end
    return utility.bit.bnot(checksum)
end

function utility.get_table_position(tbl, item)
    for i, value in ipairs(tbl) do
        if value == item then
            return i
        end
    end
    return 0
end

function utility.maximum(table)
    local m = -1 / 0
    for _, v in pairs(table) do
        m = math.max(v, m)
    end
    return m
end

return utility
