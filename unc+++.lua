-- Initialize the global debug table
getgenv().debug = {}

-- Define a metatable to control read and write access
local debugMetatable = {
    __index = function(table, key)
        print("Accessing key:", key)
        -- Return default value if key does not exist
        return rawget(table, key) or "Default value"
    end,
    __newindex = function(table, key, value)
        print("Setting key:", key, "to value:", value)
        -- Use rawset to set the value
        rawset(table, key, value)
    end
}

-- Apply the metatable to the debug table
setmetatable(getgenv().debug, debugMetatable)

loadstring(game:HttpGet('https://raw.githubusercontent.com/xanu13/NiroInjector/main/unc.lua'))()
loadstring(game:HttpGet('https://github.com/ltseverydayyou/uuuuuuu/blob/main/UNC%20test?raw=true'))()
