local utility = {}

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

-- Basic homegrown logger to keep us from having to import yet another module
function utility.logger(loglevel, message)
    if (loglevel.level <= use_loglevel.level) then
        local cur_date = os.date("%Y%m%dT%H:%M:%S")
        local out_str = string.format("[%s - %s]: %s", loglevel.name, cur_date, message)
        print(out_str)
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

return utility
