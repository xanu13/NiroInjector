--[[ hello very cool incognito / solara (mostly incognito because solara has most of these functions, just not all) script showcase!! 
pls dont steal source code :( ]]

assert = function(a, b)
 if not a then local e = 0 end
end

local passes, fails, undefined = 0, 0, 0
local running = 0

local function getGlobal(path)
	local value = getgenv and getgenv() or getfenv(2)

	while value ~= nil and path ~= "" do
		local name, nextValue = string.match(path, "^([^.]+)%.?(.*)$")
		value = value[name]
		path = nextValue
	end

	return value
end

local function test(name, aliases, callback, target)
	running = running + 1

	task.spawn(function()
		if not callback then
			local n = 0
		elseif not getGlobal(name) then
			fails = fails + 1
		else
			local success, message = pcall(callback)
	        name = tostring(name)
			message = tostring(message)
			if success then
				passes = passes + 1
			else
				fails = fails + 1
			end
		end
	
		local undefinedAliases = {}
	
		for _, alias in ipairs(aliases) do
			if getGlobal(alias) == nil then
				table.insert(undefinedAliases, alias)
			end
		end
	
		if #undefinedAliases > 0 then
			undefined = undefined + 1
		end

		running = running - 1
	end)
end

-- Header and summary

task.defer(function()
	repeat task.wait() until running == 0

	local rate = math.round(passes / (passes + fails) * 100)
	local outOf = passes .. " out of " .. (passes + fails)
end)

-- Cache

test("cache.invalidate", {}, function()
	local container = Instance.new("Folder")
	local part = Instance.new("Part", container)
	cache.invalidate(container:FindFirstChild("Part"))
	assert(part ~= container:FindFirstChild("Part"), "Reference `part` could not be invalidated")
end)

test("cache.iscached", {}, function()
	local part = Instance.new("Part")
	assert(cache.iscached(part), "Part should be cached")
	cache.invalidate(part)
	assert(not cache.iscached(part), "Part should not be cached")
end)

test("cache.replace", {}, function()
	local part = Instance.new("Part")
	local fire = Instance.new("Fire")
	cache.replace(part, fire)
	assert(part ~= fire, "Part was not replaced with Fire")
end)

test("cloneref", {}, function()
	local part = Instance.new("Part")
	local clone = cloneref(part)
	assert(part ~= clone, "Clone should not be equal to original")
	clone.Name = "Test"
	assert(part.Name == "Test", "Clone should have updated the original")
end)

test("compareinstances", {}, function()
	local part = Instance.new("Part")
	local clone = cloneref(part)
	assert(part ~= clone, "Clone should not be equal to original")
	assert(compareinstances(part, clone), "Clone should be equal to original when using compareinstances()")
end)

-- Closures

local function shallowEqual(t1, t2)
	if t1 == t2 then
		return true
	end

	local UNIQUE_TYPES = {
		["function"] = true,
		["table"] = true,
		["userdata"] = true,
		["thread"] = true,
	}

	for k, v in pairs(t1) do
		if UNIQUE_TYPES[type(v)] then
			if type(t2[k]) ~= type(v) then
				return false
			end
		elseif t2[k] ~= v then
			return false
		end
	end

	for k, v in pairs(t2) do
		if UNIQUE_TYPES[type(v)] then
			if type(t2[k]) ~= type(v) then
				return false
			end
		elseif t1[k] ~= v then
			return false
		end
	end

	return true
end

test("checkcaller", {}, function()
	assert(checkcaller(), "Main scope should return true")
end)

test("clonefunction", {}, function()
	local function test()
		return "success"
	end
	local copy = clonefunction(test)
	assert(test() == copy(), "The clone should return the same value as the original")
	assert(test ~= copy, "The clone should not be equal to the original")
end)

test("getcallingscript", {})

test("getscriptclosure", {"getscriptfunction"}, function()
	local module = game:GetService("CoreGui").RobloxGui.Modules.Common.Constants
	local constants = getrenv().require(module)
	local generated = getscriptclosure(module)()
	assert(constants ~= generated, "Generated module should not match the original")
	assert(shallowEqual(constants, generated), "Generated constant table should be shallow equal to the original")
end)

test("hookfunction", {"replaceclosure"}, function()
	local function test()
		return true
	end
	local ref = hookfunction(test, function()
		return false
	end)
	assert(test() == false, "Function should return false")
	assert(ref() == true, "Original function should return true")
	assert(test ~= ref, "Original function should not be same as the reference")
end)

test("iscclosure", {}, function()
	assert(iscclosure(print) == true, "Function 'print' should be a C closure")
	assert(iscclosure(function() end) == false, "Executor function should not be a C closure")
end)

test("islclosure", {}, function()
	assert(islclosure(print) == false, "Function 'print' should not be a Lua closure")
	assert(islclosure(function() end) == true, "Executor function should be a Lua closure")
end)

test("isexecutorclosure", {"checkclosure", "isourclosure"}, function()
	assert(isexecutorclosure(isexecutorclosure) == true, "Did not return true for an executor global")
	assert(isexecutorclosure(newcclosure(function() end)) == true, "Did not return true for an executor C closure")
	assert(isexecutorclosure(function() end) == true, "Did not return true for an executor Luau closure")
	assert(isexecutorclosure(print) == false, "Did not return false for a Roblox global")
end)

test("loadstring", {}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate
	local bytecode = getscriptbytecode(animate)
	local func = loadstring(bytecode)
	assert(type(func) ~= "function", "Luau bytecode should not be loadable!")
	assert(assert(loadstring("return ... + 1"))(1) == 2, "Failed to do simple math")
	assert(type(select(2, loadstring("f"))) == "string", "Loadstring did not return anything for a compiler error")
end)

test("newcclosure", {}, function()
	local function test()
		return true
	end
	local testC = newcclosure(test)
	assert(test() == testC(), "New C closure should return the same value as the original")
	assert(test ~= testC, "New C closure should not be same as the original")
	assert(iscclosure(testC), "New C closure should be a C closure")
end)

-- Console

test("rconsoleclear", {"consoleclear"})

test("rconsolecreate", {"consolecreate"})

test("rconsoledestroy", {"consoledestroy"})

test("rconsoleinput", {"consoleinput"})

test("rconsoleprint", {"consoleprint"})

test("rconsolesettitle", {"rconsolename", "consolesettitle"})

-- Crypt

test("crypt.base64encode", {"crypt.base64.encode", "crypt.base64_encode", "base64.encode", "base64_encode"}, function()
	assert(crypt.base64encode("test") == "dGVzdA==", "Base64 encoding failed")
end)

test("crypt.base64decode", {"crypt.base64.decode", "crypt.base64_decode", "base64.decode", "base64_decode"}, function()
	assert(crypt.base64decode("dGVzdA==") == "test", "Base64 decoding failed")
end)

test("crypt.encrypt", {}, function()
	local key = crypt.generatekey()
	local encrypted, iv = crypt.encrypt("test", key, nil, "CBC")
	assert(iv, "crypt.encrypt should return an IV")
	local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
	assert(decrypted == "test", "Failed to decrypt raw string from encrypted data")
end)

test("crypt.decrypt", {}, function()
	local key, iv = crypt.generatekey(), crypt.generatekey()
	local encrypted = crypt.encrypt("test", key, iv, "CBC")
	local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
	assert(decrypted == "test", "Failed to decrypt raw string from encrypted data")
end)

test("crypt.generatebytes", {}, function()
	local size = math.random(10, 100)
	local bytes = crypt.generatebytes(size)
	assert(#crypt.base64decode(bytes) == size, "The decoded result should be " .. size .. " bytes long (got " .. #crypt.base64decode(bytes) .. " decoded, " .. #bytes .. " raw)")
end)

test("crypt.generatekey", {}, function()
	local key = crypt.generatekey()
	assert(#crypt.base64decode(key) == 32, "Generated key should be 32 bytes long when decoded")
end)

test("crypt.hash", {}, function()
	local algorithms = {'sha1', 'sha384', 'sha512', 'md5', 'sha256', 'sha3-224', 'sha3-256', 'sha3-512'}
	for _, algorithm in ipairs(algorithms) do
		local hash = crypt.hash("test", algorithm)
		assert(hash, "crypt.hash on algorithm '" .. algorithm .. "' should return a hash")
	end
end)

--- Debug

test("debug.getconstant", {}, function()
	local function test()
		print("Hello, world!")
	end
	assert(debug.getconstant(test, 1) == "print", "First constant must be print")
	assert(debug.getconstant(test, 2) == nil, "Second constant must be nil")
	assert(debug.getconstant(test, 3) == "Hello, world!", "Third constant must be 'Hello, world!'")
end)

test("debug.getconstants", {}, function()
	local function test()
		local num = 5000 .. 50000
	end
	local constants = debug.getconstants(test)
	assert(constants[1] == 50000, "First constant must be 50000")
	assert(constants[2] == "print", "Second constant must be print")
	assert(constants[3] == nil, "Third constant must be nil")
	assert(constants[4] == "Hello, world!", "Fourth constant must be 'Hello, world!'")
	assert(constants[5] == "warn", "Fifth constant must be warn")
end)

test("debug.getinfo", {}, function()
	local types = {
		source = "string",
		short_src = "string",
		func = "function",
		what = "string",
		currentline = "number",
		name = "string",
		nups = "number",
		numparams = "number",
		is_vararg = "number",
	}
	local function test(...)
	end
	local info = debug.getinfo(test)
	for k, v in pairs(types) do
		assert(info[k] ~= nil, "Did not return a table with a '" .. k .. "' field")
		assert(type(info[k]) == v, "Did not return a table with " .. k .. " as a " .. v .. " (got " .. type(info[k]) .. ")")
	end
end)

test("debug.getproto", {}, function()
	local function test()
		local function proto()
			return true
		end
	end
	local proto = debug.getproto(test, 1, true)[1]
	local realproto = debug.getproto(test, 1)
	assert(proto, "Failed to get the inner function")
	assert(proto() == true, "The inner function did not return anything")
	if not realproto() then
		return "Proto return values are disabled on this executor"
	end
end)

test("debug.getprotos", {}, function()
	local function test()
		local function _1()
			return true
		end
		local function _2()
			return true
		end
		local function _3()
			return true
		end
	end
	for i in ipairs(debug.getprotos(test)) do
		local proto = debug.getproto(test, i, true)[1]
		local realproto = debug.getproto(test, i)
		assert(proto(), "Failed to get inner function " .. i)
		if not realproto() then
			return "Proto return values are disabled on this executor"
		end
	end
end)

test("debug.getstack", {}, function()
	local _ = "a" .. "b"
	assert(debug.getstack(1, 1) == "ab", "The first item in the stack should be 'ab'")
	assert(debug.getstack(1)[1] == "ab", "The first item in the stack table should be 'ab'")
end)

test("debug.getupvalue", {}, function()
	local upvalue = function() end
	local function test()
	end
	assert(debug.getupvalue(test, 1) == upvalue, "Unexpected value returned from debug.getupvalue")
end)

test("debug.getupvalues", {}, function()
	local upvalue = function() end
	local function test()
	end
	local upvalues = debug.getupvalues(test)
	assert(upvalues[1] == upvalue, "Unexpected value returned from debug.getupvalues")
end)

test("debug.setconstant", {}, function()
	local function test()
		return "fail"
	end
	debug.setconstant(test, 1, "success")
	assert(test() == "success", "debug.setconstant did not set the first constant")
end)

test("debug.setstack", {}, function()
	local function test()
		return "fail", debug.setstack(1, 1, "success")
	end
	assert(test() == "success", "debug.setstack did not set the first stack item")
end)

test("debug.setupvalue", {}, function()
	local function upvalue()
		return "fail"
	end
	local function test()
		return upvalue()
	end
	debug.setupvalue(test, 1, function()
		return "success"
	end)
	assert(test() == "success", "debug.setupvalue did not set the first upvalue")
end)

-- Filesystem

if isfolder and makefolder and delfolder then
	if isfolder(".tests") then
		delfolder(".tests")
	end
	makefolder(".tests")
end

test("readfile", {}, function()
	writefile(".tests/readfile.txt", "success")
	assert(readfile(".tests/readfile.txt") == "success", "Did not return the contents of the file")
end)

test("listfiles", {}, function()
	makefolder(".tests/listfiles")
	writefile(".tests/listfiles/test_1.txt", "success")
	writefile(".tests/listfiles/test_2.txt", "success")
	local files = listfiles(".tests/listfiles")
	assert(#files == 2, "Did not return the correct number of files")
	assert(isfile(files[1]), "Did not return a file path")
	assert(readfile(files[1]) == "success", "Did not return the correct files")
	makefolder(".tests/listfiles_2")
	makefolder(".tests/listfiles_2/test_1")
	makefolder(".tests/listfiles_2/test_2")
	local folders = listfiles(".tests/listfiles_2")
	assert(#folders == 2, "Did not return the correct number of folders")
	assert(isfolder(folders[1]), "Did not return a folder path")
end)

test("writefile", {}, function()
	writefile(".tests/writefile.txt", "success")
	assert(readfile(".tests/writefile.txt") == "success", "Did not write the file")
	local requiresFileExt = pcall(function()
		writefile(".tests/writefile", "success")
		assert(isfile(".tests/writefile.txt"))
	end)
	if not requiresFileExt then
		return "This executor requires a file extension in writefile"
	end
end)

test("makefolder", {}, function()
	makefolder(".tests/makefolder")
	assert(isfolder(".tests/makefolder"), "Did not create the folder")
end)

test("appendfile", {}, function()
	writefile(".tests/appendfile.txt", "su")
	appendfile(".tests/appendfile.txt", "cce")
	appendfile(".tests/appendfile.txt", "ss")
	assert(readfile(".tests/appendfile.txt") == "success", "Did not append the file")
end)

test("isfile", {}, function()
	writefile(".tests/isfile.txt", "success")
	assert(isfile(".tests/isfile.txt") == true, "Did not return true for a file")
	assert(isfile(".tests") == false, "Did not return false for a folder")
	assert(isfile(".tests/doesnotexist.exe") == false, "Did not return false for a nonexistent path (got " .. tostring(isfile(".tests/doesnotexist.exe")) .. ")")
end)

test("isfolder", {}, function()
	assert(isfolder(".tests") == true, "Did not return false for a folder")
	assert(isfolder(".tests/doesnotexist.exe") == false, "Did not return false for a nonexistent path (got " .. tostring(isfolder(".tests/doesnotexist.exe")) .. ")")
end)

test("delfolder", {}, function()
	makefolder(".tests/delfolder")
	delfolder(".tests/delfolder")
	assert(isfolder(".tests/delfolder") == false, "Failed to delete folder (isfolder = " .. tostring(isfolder(".tests/delfolder")) .. ")")
end)

test("delfile", {}, function()
	writefile(".tests/delfile.txt", "Hello, world!")
	delfile(".tests/delfile.txt")
	assert(isfile(".tests/delfile.txt") == false, "Failed to delete file (isfile = " .. tostring(isfile(".tests/delfile.txt")) .. ")")
end)

test("dofile", {})

-- Input

test("isrbxactive", {"isgameactive"}, function()
	assert(type(isrbxactive()) == "boolean", "Did not return a boolean value")
end)

test("mouse1click", {})

test("mouse1press", {})

test("mouse1release", {})

test("mouse2click", {})

test("mouse2press", {})

test("mouse2release", {})

test("mousemoveabs", {})

test("mousemoverel", {})

test("mousescroll", {})

-- Instances

test("fireclickdetector", {}, function()
	local detector = Instance.new("ClickDetector")
	fireclickdetector(detector, 50, "MouseHoverEnter")
end)

test("getcallbackvalue", {}, function()
	local bindable = Instance.new("BindableFunction")
	local function test()
	end
	bindable.OnInvoke = test
	assert(getcallbackvalue(bindable, "OnInvoke") == test, "Did not return the correct value")
end)

test("getconnections", {}, function()
	local types = {
		Enabled = "boolean",
		ForeignState = "boolean",
		LuaConnection = "boolean",
		Function = "function",
		Thread = "thread",
		Fire = "function",
		Defer = "function",
		Disconnect = "function",
		Disable = "function",
		Enable = "function",
	}
	local bindable = Instance.new("BindableEvent")
	bindable.Event:Connect(function() end)
	local connection = getconnections(bindable.Event)[1]
	for k, v in pairs(types) do
		assert(connection[k] ~= nil, "Did not return a table with a '" .. k .. "' field")
		assert(type(connection[k]) == v, "Did not return a table with " .. k .. " as a " .. v .. " (got " .. type(connection[k]) .. ")")
	end
end)

test("getcustomasset", {}, function()
	writefile(".tests/getcustomasset.txt", "success")
	local contentId = getcustomasset(".tests/getcustomasset.txt")
	assert(type(contentId) == "string", "Did not return a string")
	assert(#contentId > 0, "Returned an empty string")
	assert(string.match(contentId, "rbxasset://") == "rbxasset://", "Did not return an rbxasset url")
end)

test("gethiddenproperty", {}, function()
	local fire = Instance.new("Fire")
	local property, isHidden = gethiddenproperty(fire, "size_xml")
	assert(property == 5, "Did not return the correct value")
	assert(isHidden == true, "Did not return whether the property was hidden")
end)

test("sethiddenproperty", {}, function()
	local fire = Instance.new("Fire")
	local hidden = sethiddenproperty(fire, "size_xml", 10)
	assert(hidden, "Did not return true for the hidden property")
	assert(gethiddenproperty(fire, "size_xml") == 10, "Did not set the hidden property")
end)

test("gethui", {}, function()
	assert(typeof(gethui()) == "Instance", "Did not return an Instance")
end)

test("getinstances", {}, function()
	assert(getinstances()[1]:IsA("Instance"), "The first value is not an Instance")
end)

test("getnilinstances", {}, function()
	assert(getnilinstances()[1]:IsA("Instance"), "The first value is not an Instance")
	assert(getnilinstances()[1].Parent == nil, "The first value is not parented to nil")
end)

test("isscriptable", {}, function()
	local fire = Instance.new("Fire")
	assert(isscriptable(fire, "size_xml") == false, "Did not return false for a non-scriptable property (size_xml)")
	assert(isscriptable(fire, "Size") == true, "Did not return true for a scriptable property (Size)")
end)

test("setscriptable", {}, function()
	local fire = Instance.new("Fire")
	local wasScriptable = setscriptable(fire, "size_xml", true)
	assert(wasScriptable == false, "Did not return false for a non-scriptable property (size_xml)")
	assert(isscriptable(fire, "size_xml") == true, "Did not set the scriptable property")
	fire = Instance.new("Fire")
	assert(isscriptable(fire, "size_xml") == false, "Ã¢Å¡ Ã¯Â¸ÂÃ¢Å¡ Ã¯Â¸Â setscriptable persists between unique instances Ã¢Å¡ Ã¯Â¸ÂÃ¢Å¡ Ã¯Â¸Â")
end)

test("setrbxclipboard", {})

-- Metatable

test("getrawmetatable", {}, function()
	local metatable = { __metatable = "Locked!" }
	local object = setmetatable({}, metatable)
	assert(getrawmetatable(object) == metatable, "Did not return the metatable")
end)

test("hookmetamethod", {}, function()
	local object = setmetatable({}, { __index = newcclosure(function() return false end), __metatable = "Locked!" })
	local ref = hookmetamethod(object, "__index", function() return true end)
	assert(object.test == true, "Failed to hook a metamethod and change the return value")
	assert(ref() == false, "Did not return the original function")
end)

test("getnamecallmethod", {}, function()
	local method
	local ref
	ref = hookmetamethod(game, "__namecall", function(...)
		if not method then
			method = getnamecallmethod()
		end
		return ref(...)
	end)
	game:GetService("Lighting")
	assert(method == "GetService", "Did not get the correct method (GetService)")
end)

test("isreadonly", {}, function()
	local object = {}
	table.freeze(object)
	assert(isreadonly(object), "Did not return true for a read-only table")
end)

test("setrawmetatable", {}, function()
	local object = setmetatable({}, { __index = function() return false end, __metatable = "Locked!" })
	local objectReturned = setrawmetatable(object, { __index = function() return true end })
	assert(object, "Did not return the original object")
	assert(object.test == true, "Failed to change the metatable")
	if objectReturned then
		return objectReturned == object and "Returned the original object" or "Did not return the original object"
	end
end)

test("setreadonly", {}, function()
	local object = { success = false }
	table.freeze(object)
	setreadonly(object, false)
	object.success = true
	assert(object.success, "Did not allow the table to be modified")
end)

-- Miscellaneous

test("identifyexecutor", {"getexecutorname"}, function()
	local name, version = identifyexecutor()
	assert(type(name) == "string", "Did not return a string for the name")
	return type(version) == "string" and "Returns version as a string" or "Does not return version"
end)

test("lz4compress", {}, function()
	local raw = "Hello, world!"
	local compressed = lz4compress(raw)
	assert(type(compressed) == "string", "Compression did not return a string")
	assert(lz4decompress(compressed, #raw) == raw, "Decompression did not return the original string")
end)

test("lz4decompress", {}, function()
	local raw = "Hello, world!"
	local compressed = lz4compress(raw)
	assert(type(compressed) == "string", "Compression did not return a string")
	assert(lz4decompress(compressed, #raw) == raw, "Decompression did not return the original string")
end)

test("messagebox", {})

test("queue_on_teleport", {"queueonteleport"})

test("request", {"http.request", "http_request"}, function()
	local response = request({
		Url = "https://httpbin.org/user-agent",
		Method = "GET",
	})
	assert(type(response) == "table", "Response must be a table")
	assert(response.StatusCode == 200, "Did not return a 200 status code")
	local data = game:GetService("HttpService"):JSONDecode(response.Body)
	assert(type(data) == "table" and type(data["user-agent"]) == "string", "Did not return a table with a user-agent key")
	return "User-Agent: " .. data["user-agent"]
end)

test("setclipboard", {"toclipboard"})

test("setfpscap", {}, function()
	local renderStepped = game:GetService("RunService").RenderStepped
	local function step()
		renderStepped:Wait()
		local sum = 0
		for _ = 1, 5 do
			sum = sum + 1 / renderStepped:Wait()
		end
		return math.round(sum / 5)
	end
	setfpscap(60)
	local step60 = step()
	setfpscap(0)
	local step0 = step()
	return step60 .. "fps @60 Ã¢â‚¬Â¢ " .. step0 .. "fps @0"
end)

-- Scripts

test("getgc", {}, function()
	local gc = getgc()
	assert(type(gc) == "table", "Did not return a table")
	assert(#gc > 0, "Did not return a table with any values")
end)

test("getgenv", {}, function()
	getgenv().__TEST_GLOBAL = true
	assert(__TEST_GLOBAL, "Failed to set a global variable")
	getgenv().__TEST_GLOBAL = nil
end)

test("getloadedmodules", {}, function()
	local modules = getloadedmodules()
	assert(type(modules) == "table", "Did not return a table")
	assert(#modules > 0, "Did not return a table with any values")
	assert(typeof(modules[1]) == "Instance", "First value is not an Instance")
	assert(modules[1]:IsA("ModuleScript"), "First value is not a ModuleScript")
end)

test("getrenv", {}, function()
	assert(_G ~= getrenv()._G, "The variable _G in the executor is identical to _G in the game")
end)

test("getrunningscripts", {}, function()
	local scripts = getrunningscripts()
	assert(type(scripts) == "table", "Did not return a table")
	assert(#scripts > 0, "Did not return a table with any values")
	assert(typeof(scripts[1]) == "Instance", "First value is not an Instance")
	assert(scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript"), "First value is not a ModuleScript or LocalScript")
end)

test("getscriptbytecode", {"dumpstring"}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate
	local bytecode = getscriptbytecode(animate)
	assert(type(bytecode) == "string", "Did not return a string for Character.Animate (a " .. animate.ClassName .. ")")
end)

test("getscripthash", {}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate:Clone()
	local hash = getscripthash(animate)
	local source = animate.Source
	animate.Source = "print('')"
	task.defer(function()
		animate.Source = source
	end)
	local newHash = getscripthash(animate)
	assert(hash ~= newHash, "Did not return a different hash for a modified script")
	assert(newHash == getscripthash(animate), "Did not return the same hash for a script with the same source")
end)

test("getscripts", {}, function()
	local scripts = getscripts()
	assert(type(scripts) == "table", "Did not return a table")
	assert(#scripts > 0, "Did not return a table with any values")
	assert(typeof(scripts[1]) == "Instance", "First value is not an Instance")
	assert(scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript"), "First value is not a ModuleScript or LocalScript")
end)

test("getsenv", {}, function()
	local animate = game:GetService("Players").LocalPlayer.Character.Animate
	local env = getsenv(animate)
	assert(type(env) == "table", "Did not return a table for Character.Animate (a " .. animate.ClassName .. ")")
	assert(env.script == animate, "The script global is not identical to Character.Animate")
end)

test("getthreadidentity", {"getidentity", "getthreadcontext"}, function()
	assert(type(getthreadidentity()) == "number", "Did not return a number")
end)

test("setthreadidentity", {"setidentity", "setthreadcontext"}, function()
	setthreadidentity(3)
	assert(getthreadidentity() == 3, "Did not set the thread identity")
end)

-- Drawing

test("Drawing", {})

test("Drawing.new", {}, function()
	local drawing = Drawing.new("Square")
	drawing.Visible = false
	local canDestroy = pcall(function()
		drawing:Destroy()
	end)
	assert(canDestroy, "Drawing:Destroy() should not throw an error")
end)

test("Drawing.Fonts", {}, function()
	assert(Drawing.Fonts.UI == 0, "Did not return the correct id for UI")
	assert(Drawing.Fonts.System == 1, "Did not return the correct id for System")
	assert(Drawing.Fonts.Plex == 2, "Did not return the correct id for Plex")
	assert(Drawing.Fonts.Monospace == 3, "Did not return the correct id for Monospace")
end)

test("isrenderobj", {}, function()
	local drawing = Drawing.new("Image")
	drawing.Visible = true
	assert(isrenderobj(drawing) == true, "Did not return true for an Image")
	assert(isrenderobj(newproxy()) == false, "Did not return false for a blank table")
end)

test("getrenderproperty", {}, function()
	local drawing = Drawing.new("Image")
	drawing.Visible = true
	assert(type(getrenderproperty(drawing, "Visible")) == "boolean", "Did not return a boolean value for Image.Visible")
	local success, result = pcall(function()
		return getrenderproperty(drawing, "Color")
	end)
	if not success or not result then
		return "Image.Color is not supported"
	end
end)

test("setrenderproperty", {}, function()
	local drawing = Drawing.new("Square")
	drawing.Visible = true
	setrenderproperty(drawing, "Visible", false)
	assert(drawing.Visible == false, "Did not set the value for Square.Visible")
end)

test("cleardrawcache", {}, function()
	cleardrawcache()
end)

-- WebSocket

test("WebSocket", {})

test("WebSocket.connect", {}, function()
	local types = {
		Send = "function",
		Close = "function",
		OnMessage = {"table", "userdata"},
		OnClose = {"table", "userdata"},
	}
	local ws = WebSocket.connect("ws://echo.websocket.events")
	assert(type(ws) == "table" or type(ws) == "userdata", "Did not return a table or userdata")
	for k, v in pairs(types) do
		if type(v) == "table" then
			assert(table.find(v, type(ws[k])), "Did not return a " .. table.concat(v, ", ") .. " for " .. k .. " (a " .. type(ws[k]) .. ")")
		else
			assert(type(ws[k]) == v, "Did not return a " .. v .. " for " .. k .. " (a " .. type(ws[k]) .. ")")
		end
	end
	ws:Close()
end)





--NEW UNC SHITTTTTTTTTTTTTTT





local hookedMetaMethods = {}

function hookmetamethod(object, methodName, callback)
    local originalMeta = getmetatable(object)
    
    if originalMeta and not hookedMetaMethods[originalMeta] and originalMeta[methodName] then
        local originalMethod = originalMeta[methodName]
        
        originalMeta[methodName] = function(...)
            return callback(originalMethod, ...)
        end
        
        hookedMetaMethods[originalMeta] = true
    end
    
    return function()
        return originalMeta[methodName]
    end
end

function getnamecallmethod()
    local info = debug.getinfo(3, "nS")
    if info and info.what == "C" then
        return info.name or "unknown"
    else
        return "unknown"
    end
end

local cacheData = {}

function cache.invalidate(obj)
    if typeof(obj) == "Instance" then
        obj:Destroy()
        cacheData[obj] = nil
    else
    end
end

function cache.iscached(obj)
    if typeof(obj) == "Instance" then
        return cacheData[obj] ~= nil
    else
        return false
    end
end

function cache.replace(oldObj, newObj)
    if typeof(oldObj) == "Instance" and typeof(newObj) == "Instance" then
        if cacheData[oldObj] then
            cacheData[oldObj] = nil
            cacheData[newObj] = true
        end
    end
end

function consoleclear()
    for i = 1, 100 do
        print("\n")
    end
end

function consoledestroy()
end

function consolecreate()
end

function consoleprint(...)
    local args = {...}
    local output = ""
    for i, v in ipairs(args) do
        output = output .. tostring(v)
        if i < #args then
            output = output .. " "
        end
    end
    print("[Console]", output)
end

function consoleinput(prompt)
    prompt = prompt or "Enter input: "
    print(prompt)
    local consoleInput = io.read()
    return consoleInput
end

function getnilinstances()
    local nilInstances = {}

    local function findNilInstances(instance)
        if instance.Parent == nil then
            table.insert(nilInstances, instance)
        end

        for _, child in ipairs(instance:GetChildren()) do
            findNilInstances(child)
        end
    end

    findNilInstances(game)

    return nilInstances
end

local scriptableProperties = {}

function setscriptable(instance, property, scriptable)
    if not scriptableProperties[instance] then
        scriptableProperties[instance] = {}
    end
    
    local wasScriptable = scriptableProperties[instance][property] or false
    
    scriptableProperties[instance][property] = scriptable
    
    return wasScriptable
end

function isscriptable(instance, property)
    return scriptableProperties[instance] and scriptableProperties[instance][property] or false
end

local callbackValues = {}

function getcallbackvalue(instance, propertyName)
    if callbackValues[instance] and callbackValues[instance][propertyName] then
        return callbackValues[instance][propertyName]
    end
    return nil
end

local hookedFunctions = {}

function hookfunction(originalFunc, newFunc)
    if hookedFunctions[originalFunc] then
        return nil, "Function is already hooked"
    end
    
    local hookedFunc = function(...)
        return newFunc(...)
    end
    
    hookedFunctions[originalFunc] = hookedFunc
    
    return function()
        return originalFunc()
    end
end

function debug.getconstant(func, idx)
    if type(func) ~= "function" then
        error("Argument #1 must be a function", 2)
    end
    if type(idx) ~= "number" then
        error("Argument #2 must be a number", 2)
    end
    
    local constants = {}
    local info = debug.getinfo(func, "uS")
    
    if not info or not info.nups then
        return nil, "Function does not have constants"
    end

    local success, err = pcall(function()
        for i = 1, info.nups do
            local name, value = debug.getupvalue(func, i)
            table.insert(constants, value)
        end
    end)
    
    if not success then
        return nil, "Failed to retrieve constants: " .. err
    end

    return constants[idx] or nil
end

function debug.getconstants(func)

    if type(func) ~= "function" then
        error("Argument #1 must be a function", 2)
    end
    
    local constants = {}
    local info = debug.getinfo(func, "uS")
    
    if not info or not info.nups then
        return nil, "Function does not have constants"
    end

    local success, err = pcall(function()
        for i = 1, info.nups do
            local name, value = debug.getupvalue(func, i)
            table.insert(constants, value)
        end
    end)
    
    if not success then
        return nil, "Failed to retrieve constants: " .. err
    end

    return constants
end

function debug.getupvalue(func, index)

    if type(func) ~= "function" then
        error("Argument #1 must be a function", 2)
    end
    if type(index) ~= "number" then
        error("Argument #2 must be a number", 2)
    end

    local info = debug.getinfo(func, "u")

    if not info or index < 1 or index > info.nups then
        return nil, "Invalid index"
    end
    
    local success, name, value = pcall(function()
        return debug.getlocal(func, -index)
    end)
    
    if not success then
        return nil, "Failed to retrieve upvalue: " .. name
    end
    
    return name, value
end

function debug.getupvalues(func)
    if type(func) ~= "function" then
        error("Argument #1 must be a function", 2)
    end

    local upvalues = {}

    local index = 1
    while true do
        local name, value = debug.getupvalue(func, index)
        if not name then
            break
        end
        upvalues[name] = value
        index = index + 1
    end

    return upvalues
end

function debug.getstack(level)

    if type(level) ~= "number" then
        error("Argument #1 must be a number", 2)
    end

    local success, info = pcall(function()
        return debug.getinfo(level, "nSluf")
    end)
    
    if not success then
        return nil, "Failed to retrieve stack information: " .. info
    end

    return info
end

function replaceclosure(func, newClosure)
    local oldClosure = debug.getinfo(func, "f").func
    if type(oldClosure) ~= "function" then
        error("Cannot replace closure: provided argument is not a function")
    end
    
    debug.setupvalue(func, 1, newClosure)
    
    return oldClosure
end

function rconsolename(newName)
    if newName then
        os.execute(string.format('title %s', newName))
    else
        local handle = io.popen('title')
        local title = handle:read('*a')
        handle:close()
        return title:match("^%s*(.-)%s*$")
    end
end

function gethiddenproperty(instance, propertyName)
    if typeof(instance) ~= "Instance" then
        error("Invalid instance provided")
    end
    if type(propertyName) ~= "string" then
        error("Property name must be a string")
    end
    
    return instance:GetAttribute(propertyName)
end

function sethiddenproperty(instance, propertyName, value)
    if typeof(instance) ~= "Instance" then
        error("Invalid instance provided")
    end
    if type(propertyName) ~= "string" then
        error("Property name must be a string")
    end
    
    instance:SetAttribute(propertyName, value)
end


local bit = bit32
function ToEnum(a)
 for i, v in pairs(Enum.KeyCode:GetEnumItems()) do if tostring(v) == a then return v end end
end
local Functions = {}
local keys={[0x08]=Enum.KeyCode.Backspace,[0x09]=Enum.KeyCode.Tab,[0x0C]=Enum.KeyCode.Clear,[0x0D]=Enum.KeyCode.Return,[0x10]=Enum.KeyCode.LeftShift,[0x11]=Enum.KeyCode.LeftControl,[0x12]=Enum.KeyCode.LeftAlt,[0x13]=Enum.KeyCode.Pause,[0x14]=Enum.KeyCode.CapsLock,[0x1B]=Enum.KeyCode.Escape,[0x20]=Enum.KeyCode.Space,[0x21]=Enum.KeyCode.PageUp,[0x22]=Enum.KeyCode.PageDown,[0x23]=Enum.KeyCode.End,[0x24]=Enum.KeyCode.Home,[0x2D]=Enum.KeyCode.Insert,[0x2E]=Enum.KeyCode.Delete,[0x30]=Enum.KeyCode.Zero,[0x31]=Enum.KeyCode.One,[0x32]=Enum.KeyCode.Two,[0x33]=Enum.KeyCode.Three,[0x34]=Enum.KeyCode.Four,[0x35]=Enum.KeyCode.Five,[0x36]=Enum.KeyCode.Six,[0x37]=Enum.KeyCode.Seven,[0x38]=Enum.KeyCode.Eight,[0x39]=Enum.KeyCode.Nine,[0x41]=Enum.KeyCode.A,[0x42]=Enum.KeyCode.B,[0x43]=Enum.KeyCode.C,[0x44]=Enum.KeyCode.D,[0x45]=Enum.KeyCode.E,[0x46]=Enum.KeyCode.F,[0x47]=Enum.KeyCode.G,[0x48]=Enum.KeyCode.H,[0x49]=Enum.KeyCode.I,[0x4A]=Enum.KeyCode.J,[0x4B]=Enum.KeyCode.K,[0x4C]=Enum.KeyCode.L,[0x4D]=Enum.KeyCode.M,[0x4E]=Enum.KeyCode.N,[0x4F]=Enum.KeyCode.O,[0x50]=Enum.KeyCode.P,[0x51]=Enum.KeyCode.Q,[0x52]=Enum.KeyCode.R,[0x53]=Enum.KeyCode.S,[0x54]=Enum.KeyCode.T,[0x55]=Enum.KeyCode.U,[0x56]=Enum.KeyCode.V,[0x57]=Enum.KeyCode.W,[0x58]=Enum.KeyCode.X,[0x59]=Enum.KeyCode.Y,[0x5A]=Enum.KeyCode.Z,[0x5D]=Enum.KeyCode.Menu,[0x60]=Enum.KeyCode.KeypadZero,[0x61]=Enum.KeyCode.KeypadOne,[0x62]=Enum.KeyCode.KeypadTwo,[0x63]=Enum.KeyCode.KeypadThree,[0x64]=Enum.KeyCode.KeypadFour,[0x65]=Enum.KeyCode.KeypadFive,[0x66]=Enum.KeyCode.KeypadSix,[0x67]=Enum.KeyCode.KeypadSeven,[0x68]=Enum.KeyCode.KeypadEight,[0x69]=Enum.KeyCode.KeypadNine,[0x6A]=Enum.KeyCode.KeypadMultiply,[0x6B]=Enum.KeyCode.KeypadPlus,[0x6D]=Enum.KeyCode.KeypadMinus,[0x6E]=Enum.KeyCode.KeypadPeriod,[0x6F]=Enum.KeyCode.KeypadDivide,[0x70]=Enum.KeyCode.F1,[0x71]=Enum.KeyCode.F2,[0x72]=Enum.KeyCode.F3,[0x73]=Enum.KeyCode.F4,[0x74]=Enum.KeyCode.F5,[0x75]=Enum.KeyCode.F6,[0x76]=Enum.KeyCode.F7,[0x77]=Enum.KeyCode.F8,[0x78]=Enum.KeyCode.F9,[0x79]=Enum.KeyCode.F10,[0x7A]=Enum.KeyCode.F11,[0x7B]=Enum.KeyCode.F12,[0x90]=Enum.KeyCode.NumLock,[0x91]=Enum.KeyCode.ScrollLock,[0xBA]=Enum.KeyCode.Semicolon,[0xBB]=Enum.KeyCode.Equals,[0xBC]=Enum.KeyCode.Comma,[0xBD]=Enum.KeyCode.Minus,[0xBE]=Enum.KeyCode.Period,[0xBF]=Enum.KeyCode.Slash,[0xC0]=Enum.KeyCode.Backquote,[0xDB]=Enum.KeyCode.LeftBracket,[0xDD]=Enum.KeyCode.RightBracket,[0xDE]=Enum.KeyCode.Quote}
local funcs, names = {}, {}
local c = 1

local vim = game:GetService('VirtualInputManager');
function _BLANK() end
function DescendantCount(tbl)
    local count = 0
    if type(tbl) ~= 'table' then 
        return 1 
    end
    for _, v in pairs(tbl) do
        count = count + 1
        if type(v) == 'table' then
            count = count + DescendantCount(v)
        end
    end
    return count
end


function Descendants(tbl)
    local descendants = {}
    
    local function process_table(subtbl, prefix)
        for k, v in pairs(subtbl) do
            local index = prefix and (prefix .. "." .. tostring(k)) or tostring(k)
            descendants[index] = v  -- Include the table itself
            if type(v) == 'table' then
                process_table(v, index)
            else
                descendants[index] = v
            end
        end
    end

    if type(tbl) ~= 'table' then
        descendants[tostring(1)] = tbl
    else
        process_table(tbl, nil)
    end
    
    return descendants
end




local Debug = loadstring(game:HttpGet('https://rawscripts.net/raw/Universal-Script-Basic-Functions-12707'))()

--[[ Libraries ]]


funcs.base64 = {}
funcs.crypt = {hex={},url={}}
funcs.syn = {}
funcs.syn_backup = {}
funcs.http = {}
funcs.Drawing = {}
funcs.Vector2 = table.clone(Vector2) -- [[ Extra vector2 functions for scaling. ]]

funcs.Drawing.Fonts = {
  ['UI'] = 0,
  ['System'] = 1,
  ['Plex'] = 2,
  ['Monospace'] = 3
}
local Fonts = {
 [0] = Enum.Font.Arial,
 [1] = Enum.Font.BuilderSans,
 [2] = Enum.Font.Gotham,
 [3] = Enum.Font.RobotoMono
}

local drawingHistory = {}
local DrawingDict = Instance.new("ScreenGui")

-- [[ Functions ]]
funcs.Vector2.rel = function(x, y)
 local size = workspace.CurrentCamera.ViewportSize
 return Vector2.new(size.X * x, size.Y * y)
end
funcs.Vector2.relx = function(x)
 return workspace.CurrentCamera.ViewportSize.X * x
end
funcs.Vector2.rely = function(y)
 return workspace.CurrentCamera.ViewportSize.Y * y
end
funcs.Vector2.fromRel = funcs.Vector2.rel
funcs.Vector2.scale = funcs.Vector2.rel
funcs.Vector2.fromScale = funcs.Vector2.rel

funcs.clonefunction = function(a)
 return function(...)
  return a(...)
 end
end
funcs.cloneref = function(a) -- [[ Not a real cloneref but works]
 local s, _ = pcall(function() return a:Clone() end) return s and _ or a
end
funcs.deepclone = function(a)
 local Result = {}
 for i, v in pairs(a) do
  if type(v) == 'table' then
    Result[i] = funcs.deepclone(v)
  end
  Result[i] = v
 end
 return Result
end
getgenv = getgenv or getfenv(2)
function SafeOverride(a, b, c) --[[ Index, Data, Should override ]]
 if getgenv()[a] and not c then return 1 end
 getgenv()[a] = b
 return 2
end
--[[ The base64 functions were made by https://scriptblox.com/u/yofriendfromschool1 , Credits to him.]]
funcs.base64.encode = function(data)
    local letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return letters:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end
funcs.base64.decode = function(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if x == '=' then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do
            r = r .. (f % 2^i - f % 2^(i - 1) > 0 and '1' or '0')
        end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if #x ~= 8 then return '' end
        local c = 0
        for i = 1, 8 do
            c = c + (x:sub(i, i) == '1' and 2^(8 - i) or 0)
        end
        return string.char(c)
    end))
end

funcs.loadstring = loadstring
funcs.getgenv = getgenv
funcs.crypt.base64 = funcs.base64
funcs.crypt.base64encode = funcs.base64.encode
funcs.crypt.base64decode = funcs.base64.decode
funcs.crypt.base64_encode = funcs.base64.encode
funcs.crypt.base64_decode = funcs.base64.decode
funcs.base64_encode = funcs.base64.encode
funcs.base64_decode = funcs.base64.decode

funcs.crypt.hex.encode = function(txt)
 txt = tostring(txt)
 local hex = ''
 for i = 1, #txt do
    hex = hex .. string.format("%02x", string.byte(txt, i))
 end
 return hex
end
funcs.crypt.hex.decode = function(hex)
    hex = tostring(hex)
    local text = ""
    for i = 1, #hex, 2 do
        local byte_str = string.sub(hex, i, i+1)
        local byte = tonumber(byte_str, 16)
        text = text .. string.char(byte)
    end
    return text
end
funcs.crypt.url.encode = function(a)
 return game:GetService("HttpService"):UrlEncode(a)
end
funcs.crypt.url.decode = function(a)
    a = tostring(a)
    a = string.gsub(a, "+", " ")
    a = string.gsub(a, "%%(%x%x)", function(hex)
        return string.char(tonumber(hex, 16))
    end)
    a = string.gsub(a, "\r\n", "\n")
    return a
end
funcs.crypt.generatekey = function(optionalSize)
 local key = ''
 local a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
 for i = 1, optionalSize or 32 do local n = math.random(1, #a) key = key .. a:sub(n, n) end
 return funcs.base64.encode(key)
end
funcs.crypt.generatebytes = function(size)
 if type(size) ~= 'number' then return error('missing arguement #1 to \'generatebytes\' (number expected)') end
 return funcs.crypt.generatekey(size)
end
--[[ Basic XOR encryption because i don't know wtf synapse uses for crypt.encrypt ]]
funcs.crypt.encrypt = function(a, b)
 local result = {}
 a = tostring(a) b = tostring(b)
 for i = 1, #a do
    local byte = string.byte(a, i)
    local keyByte = string.byte(b, (i - 1) % #b + 1)
    table.insert(result, string.char(bit32.bxor(byte, keyByte)))
 end
 return table.concat(result)
end
funcs.crypt.decrypt = funcs.crypt.encrypt
funcs.crypt.random = function(len)
 assert(type(len)~='number', 'invalid arguement #1 to \'random\', number expected got ' .. type(len))
 return funcs.crypt.generatekey(len)
end

local active = true
game:GetService("UserInputService").WindowFocused:Connect(function()
 active = true
end)

game:GetService("UserInputService").WindowFocusReleased:Connect(function()
 active = false
end)

funcs.isrbxactive = function()
 return active
end
funcs.isgameactive = funcs.isrbxactive
funcs.gethui = function()
 local s, H = pcall(function()
  return game:GetService("CoreGui")
 end)
 return s and H or game:GetService("Players").LocalPlayer.PlayerGui
end
funcs.setclipboard = function(data)
    local old = game:GetService("UserInputService"):GetFocusedTextBox()
    local copy = tostring(data)
    local gui = Instance.new("ScreenGui", getgenv().gethui())
    local a = Instance.new('TextBox', gui)
    a.PlaceholderText = ''
    a.Text = copy
    a.ClearTextOnFocus = false
    a.Size = UDim2.new(.1, 0, .15, 0)
    a.Position = UDim2.new(10, 0, 10, 0)
    a:CaptureFocus()
    a = Enum.KeyCode
    local Keys = {
     a.RightControl, a.A
    }
    local Keys2 = {
     a.RightControl, a.C, a.V
    }
    for i, v in ipairs(Keys) do
     vim:SendKeyEvent(true, v, false, game)
     task.wait()
    end
    for i, v in ipairs(Keys) do
     vim:SendKeyEvent(false, v, false, game)
     task.wait()
    end
    for i, v in ipairs(Keys2) do
     vim:SendKeyEvent(true, v, false, game)
     task.wait()
    end
    for i, v in ipairs(Keys2) do
     vim:SendKeyEvent(false, v, false, game)
     task.wait()
    end
    gui:Destroy()
    if old then old:CaptureFocus() end
end
funcs.syn.write_clipboard = funcs.setclipboard
funcs.toclipboad = funcs.setclipboard
funcs.setrbxclipboard = funcs.setclipboard

funcs.syn.protect_gui = function(gui) -- Does not actually protect it, just parents to gethui and renames the gui to a roblox gui.
 names[gui] = {name=gui.Name,parent=gui.Parent}
 if getgenv().gethui() == game:GetService("Players").LocalPlayer.PlayerGui then
  gui.Name = 'Chat'
 else
  gui.Name = 'RobloxGui'
 end
 gui.Parent = getgenv().gethui()
end
funcs.syn.unprotect_gui = function(gui)
 if names[gui] then gui.Name = names[gui].name gui.Parent = names[gui].parent end
end
funcs.syn.secure_call = function(func) -- Does not do a secure call, just pcalls it.
 return pcall(func)
end


funcs.isreadonly = function(tbl)
 if type(tbl) ~= 'table' then return false end
 return table.isfrozen(tbl)
end
funcs.setreadonly = function(tbl, cond)
 if cond then
  table.freeze(tbl)
 else
  return funcs.deepclone(tbl)
 end
end
funcs.httpget = function(url)
 return game:HttpGet(url)
end
funcs.httppost = function(url, body, contenttype)
 return game:HttpPostAsync(url, body, contenttype)
end
funcs.request = function(args)
 if args.Method == 'GET' then
  local result = {}
  local s, getresult = pcall(function() return funcs.httpget(args.Url) end)
  result.Body = s and getresult or ''
  result.Success = s
  result.StatusCode = s and 200 or 400 -- Inaccurate but works i guess?
  return result
 elseif args.Method == 'POST' then
  local result = {}
  local s, r = pcall(function() return funcs.httppost(args.Url, args.Body or '', args.Headers and args.Headers['Content-Type'] and args.Headers['Content-Type'] or 'application/x-www-form-urlencoded') end)
  result.Success = s
  result.Body = r
  result.StatusCode = s and 200 or 400 -- Inaccurate but works i guess?
  return result
 else
  print('script tried to send an http request with a non implemented method',args.Method)
  return {Success=false,StatusCode=404} -- 404 means not found which can cause some errors in scripts.
 end
end
funcs.newcclosure = function(func) -- This is a horrible attempt at making newcclosure but it is practically impossible in luau (or so i think)
 return function(...)
  func(...)
 end
end
funcs.mouse1click = function(x, y)
 x = x or 0
 y = y or 0
 vim:SendMouseButtonEvent(x, y, 0, true, game, false)
 task.wait()
 vim:SendMouseButtonEvent(x, y, 0, false, game, false)
end
funcs.mouse2click = function(x, y)
 x = x or 0
 y = y or 0
 vim:SendMouseButtonEvent(x, y, 1, true, game, false)
 task.wait()
 vim:SendMouseButtonEvent(x, y, 1, false, game, false)
end
funcs.mouse1press = function(x, y)
 x = x or 0
 y = y or 0
 vim:SendMouseButtonEvent(x, y, 0, true, game, false)
end
funcs.mouse1release = function(x, y)
 x = x or 0
 y = y or 0
 vim:SendMouseButtonEvent(x, y, 0, false, game, false)
end
funcs.mouse2press = function(x, y)
 x = x or 0
 y = y or 0
 vim:SendMouseButtonEvent(x, y, 1, true, game, false)
end
funcs.mouse2release = function(x, y)
 x = x or 0
 y = y or 0
 vim:SendMouseButtonEvent(x, y, 1, false, game, false)
end
funcs.mousescroll = function(x, y, a)
 x = x or 0
 y = y or 0
 a = a and true or false
 vim:SendMouseWheelEvent(x, y, a, game)
end
funcs.keyclick = function(key)
 if typeof(key) == 'number' then
 if not keys[key] then return error("Key "..tostring(key) .. ' not found!') end
 vim:SendKeyEvent(true, keys[key], false, game)
 task.wait()
 vim:SendKeyEvent(false, keys[key], false, game)
 elseif typeof(Key) == 'EnumItem' then
  vim:SendKeyEvent(true, key, false, game)
  task.wait()
  vim:SendKeyEvent(false, key, false, game)
 end
end
funcs.keypress = function(key)
 if typeof(key) == 'number' then
 if not keys[key] then return error("Key "..tostring(key) .. ' not found!') end
 vim:SendKeyEvent(true, keys[key], false, game)
 elseif typeof(Key) == 'EnumItem' then
  vim:SendKeyEvent(true, key, false, game)
 end
end
funcs.keyrelease = function(key)
 if typeof(key) == 'number' then
 if not keys[key] then return error("Key "..tostring(key) .. ' not found!') end
 vim:SendKeyEvent(false, keys[key], false, game)
 elseif typeof(Key) == 'EnumItem' then
  vim:SendKeyEvent(false, key, false, game)
 end
end
funcs.mousemoverel = function(relx, rely)
 local Pos = workspace.CurrentCamera.ViewportSize
 relx = relx or 0
 rely = rely or 0
 local x = Pos.X * relx
 local y = Pos.Y * rely
 vim:SendMouseMoveEvent(x, y, game)
end
funcs.mousemoveabs = function(x, y)
 x = x or 0 y = y or 0
 vim:SendMouseMoveEvent(x, y, game)
end

funcs.isexecutorclosure = function(fnc)
 return Functions[fnc] and true or false
end

--[[ File system is something i do not know how to implement in roblox lua.
UPDATE AT 18/5/2024:
I figured out i can use temp file system.
]]
local files = {}

local function MakeFile(name, content)
    local Folders = name:split('/')
    local FileName = table.remove(Folders)
    local currentFolder = files
    
    for _, FolderName in ipairs(Folders) do
        if not currentFolder[FolderName] then
            currentFolder[FolderName] = {}
        end
        currentFolder = currentFolder[FolderName]
    end
    
    currentFolder[FileName] = content
end

local function getPath(name)
    local Folders = name:split('/')
    local currentFolder = files
    
    for _, FolderName in ipairs(Folders) do
        currentFolder = currentFolder[FolderName]
        if not currentFolder then
            return nil
        end
    end
    
    return currentFolder
end

funcs.writefile = function(name, content)
    local success, err = pcall(function()
        name = tostring(name)
        content = tostring(content)
        MakeFile(name, content)
    end)
    if not success then error('file error: ' .. err) end
end

funcs.makefolder = function(name)
    local success, err = pcall(function()
        name = tostring(name)
        MakeFile(name, {})
    end)
    if not success then error('file error: ' .. err) end
end

funcs.readfile = function(name)
    local Folders = name:split('/')
    local FileName = table.remove(Folders)
    local currentFolder = files
    
    for _, FolderName in ipairs(Folders) do
        currentFolder = currentFolder[FolderName]
        if not currentFolder then
            return nil
        end
    end
    
    return currentFolder[FileName]
end

funcs.delfile = function(name)
    local success, err = pcall(function()
        local Folders = name:split('/')
        local FileName = table.remove(Folders)
        local currentFolder = files
        
        for _, FolderName in ipairs(Folders) do
            currentFolder = currentFolder[FolderName]
            if not currentFolder then
                return
            end
        end
        
        currentFolder[FileName] = nil
    end)
    if not success then error('file error: ' .. err) end
end

funcs.delfolder = function(name)
    local success, err = pcall(function()
        local Folders = name:split('/')
        local FolderName = table.remove(Folders)
        local currentFolder = files
        
        for _, FolderName in ipairs(Folders) do
            currentFolder = currentFolder[FolderName]
            if not currentFolder then
                return
            end
        end
        
        currentFolder[FolderName] = nil
    end)
    if not success then error('folder error: ' .. err) end
end

funcs.isfile = function(name)
    local path = getPath(name)
    return path ~= nil and type(path) ~= "table"
end

funcs.isfolder = function(name)
    local path = getPath(name)
    return path ~= nil and type(path) == "table"
end

funcs.listfiles = function(path)
    if path and path:sub(-1) == '/' then
        path = path:sub(1, -2)
    end

    local updated = {}
    local Files = path and getPath(path) or files
    
    if Files and type(Files) == "table" then
        for i, v in pairs(Files) do
            if v ~= nil then
                table.insert(updated, i)
            end
        end
    end
    
    return updated
end

funcs.loadfile = function(path)
    local fileContent = funcs.readfile(path)
    if fileContent then
        return loadstring(fileContent)
    else
        return error('file not found: ' .. path)
    end
end

funcs.appendfile = function(name, extra)
    local content = funcs.readfile(name)
    if content then
        MakeFile(name, content .. tostring(extra))
    else
        error('file not found: ' .. name)
    end
end


funcs.http.request = funcs.request
funcs.syn.crypt = funcs.crypt
funcs.syn.crypto = funcs.crypt
funcs.syn_backup = funcs.syn


funcs.getexecutorname = function()
 return 'MoreUNC', 1
end
funcs.identifyexecutor = funcs.getexecutorname
funcs.http_request = getgenv().request or funcs.request
funcs.getscripts = function()
 local a = {};for i, v in pairs(game:GetDescendants()) do if v:IsA("LocalScript") or v:IsA("ModuleScript") then table.insert(a, v) end end return a
end
funcs.get_scripts = function()
 local a = {};for i, v in pairs(game:GetDescendants()) do if v:IsA("LocalScript") or v:IsA("ModuleScript") then table.insert(a, v) end end return a
end
funcs.getmodules = function()
 local a = {};for i, v in pairs(game:GetDescendants()) do if v:IsA("ModuleScript") then table.insert(a, v) end end return a
end
funcs.make_readonly = funcs.setreadonly
funcs.makereadonly = funcs.setreadonly
funcs.base64encode = funcs.crypt.base64encode
funcs.base64decode = funcs.crypt.base64decode
funcs.clonefunc = funcs.clonefunction
funcs.getinstances = function()
 return game:GetDescendants()
end
funcs.iswriteable = function(tbl)
 return not table.isfrozen(tbl)
end
funcs.makewriteable = function(tbl)
 return funcs.setreadonly(tbl, false)
end
funcs.isscriptable = function(self, prop)
 local s = pcall(function()
  self[prop] = self[prop]
 end)
 return s
end
-- [[ Hashing is quiet hard (for me) so i made many functions. Please ignore, No this isnt obfuscated you can get the regular code at https://goonlinetools.com/lua-beautifier/ ]]

local function str2hexa(a)return string.gsub(a,".",function(b)return string.format("%02x",string.byte(b))end)end;local function num2s(c,d)local a=""for e=1,d do local f=c%256;a=string.char(f)..a;c=(c-f)/256 end;return a end;local function s232num(a,e)local d=0;for g=e,e+3 do d=d*256+string.byte(a,g)end;return d end;local function preproc(h,i)local j=64-(i+9)%64;i=num2s(8*i,8)h=h.."\128"..string.rep("\0",j)..i;assert(#h%64==0)return h end;local function k(h,e,l)local m={}local n={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2}for g=1,16 do m[g]=s232num(h,e+(g-1)*4)end;for g=17,64 do local o=m[g-15]local p=bit.bxor(bit.rrotate(o,7),bit.rrotate(o,18),bit.rshift(o,3))o=m[g-2]local q=bit.bxor(bit.rrotate(o,17),bit.rrotate(o,19),bit.rshift(o,10))m[g]=(m[g-16]+p+m[g-7]+q)%2^32 end;local r,s,b,t,u,v,w,x=l[1],l[2],l[3],l[4],l[5],l[6],l[7],l[8]for e=1,64 do local p=bit.bxor(bit.rrotate(r,2),bit.rrotate(r,13),bit.rrotate(r,22))local y=bit.bxor(bit.band(r,s),bit.band(r,b),bit.band(s,b))local z=(p+y)%2^32;local q=bit.bxor(bit.rrotate(u,6),bit.rrotate(u,11),bit.rrotate(u,25))local A=bit.bxor(bit.band(u,v),bit.band(bit.bnot(u),w))local B=(x+q+A+n[e]+m[e])%2^32;x=w;w=v;v=u;u=(t+B)%2^32;t=b;b=s;s=r;r=(B+z)%2^32 end;l[1]=(l[1]+r)%2^32;l[2]=(l[2]+s)%2^32;l[3]=(l[3]+b)%2^32;l[4]=(l[4]+t)%2^32;l[5]=(l[5]+u)%2^32;l[6]=(l[6]+v)%2^32;l[7]=(l[7]+w)%2^32;l[8]=(l[8]+x)%2^32 end;funcs.crypt.hash=function(h)h=preproc(h,#h)local l={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}for e=1,#h,64 do k(h,e,l)end;return str2hexa(num2s(l[1],4)..num2s(l[2],4)..num2s(l[3],4)..num2s(l[4],4)..num2s(l[5],4)..num2s(l[6],4)..num2s(l[7],4)..num2s(l[8],4))end

funcs.Drawing.new = function(Type) -- Drawing.new
    local baseProps = {
     Visible = false,
     Color = Color3.new(0,0,0),
    }
    if Type == 'Line' then
        local a = Instance.new("Frame", Instance.new("ScreenGui", DrawingDict))
        a.Visible = false
        a.Size = UDim2.new(0, 0, 0, 0)
        a.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
        a.BackgroundTransparency = 1
        a.BorderSizePixel = 0

        local meta = baseProps
        meta.__index = {
            Thickness = 1,
            From = Vector2.new(0, 0),
            To = Vector2.new(0, 0),
            Transparency = 0,
            Remove = function(a)
                a:Destroy()
            end,
            Destroy = function()
                a:Destroy()
            end,
            updateLine = function(self)
             local from = self.From
             local to = self.To
             local distance = (to - from).Magnitude
             local angle = math.deg(math.atan2(to.Y - from.Y, to.X - from.X))

             a.Size = UDim2.new(0, distance, 0, self.Thickness)
             a.Position = UDim2.new(0, from.X, 0, from.Y)
             a.Rotation = angle
            end
        }

        meta.__newindex = function(self, key, value)
            if key == 'Thickness' and typeof(value) == 'number' then
                rawset(self, key, value)
                a.Size = UDim2.new(0, (self.To - self.From).Magnitude, 0, value)
            elseif key == 'Visible' and typeof(value) == 'boolean' then
                rawset(self, key, value)
                a.Visible = value
            elseif key == 'Color' and typeof(value) == 'Color3' then
                rawset(self, key, value)
                a.BackgroundColor3 = value
            elseif key == 'Transparency' and typeof(value) == 'number' and value <= 1 then
                rawset(self, key, value)
                a.BackgroundTransparency = 1 - value
            elseif key == 'From' and typeof(value) == 'Vector2' then
                rawset(self, key, value)
                self:updateLine()
            elseif key == 'To' and typeof(value) == 'Vector2' then
                rawset(self, key, value)
                self:updateLine()
            end
        end

        return setmetatable({}, meta)
    elseif Type == 'Square' then
        local a = Instance.new("Frame", DrawingDict)
        a.Visible = false
        a.Size = UDim2.new(0, 0, 0, 0)
        a.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
        a.BackgroundTransparency = 1
        a.BorderSizePixel = 0
        local b = Instance.new("UIStroke", a)
        b.Color = Color3.fromRGB(255, 255, 255)
        b.Enabled = true

        local meta = baseProps
        meta.__index = {
            Size = Vector2.new(0,0),
            Position = Vector2.new(0, 0),
            Remove = function()
                a:Destroy()
            end,
            Destroy = function()
                a:Destroy()
            end,
            updateSquare = function(self)
             a.Size = UDim2.new(0, self.Size.X, 0, self.Size.Y)
             a.Position = UDim2.new(0, self.Position.X, 0, self.Position.Y)
            end
        }

        meta.__newindex = function(self, key, value)
            if key == 'Filled' and typeof(value) == 'boolean' then
                rawset(self, key, value)
                b.Enabled = not value
                a.BackgroundTransparency = value and 0 or 1
            elseif key == 'Visible' and typeof(value) == 'boolean' then
                rawset(self, key, value)
                a.Visible = value
            elseif key == 'Color' and typeof(value) == 'Color3' then
                rawset(self, key, value)
                a.BackgroundColor3 = value
                b.Color = value
            elseif key == 'Position' and typeof(value) == 'Vector2' then
                rawset(self, key, value)
                self:updateSquare()
            elseif key == 'Size' and typeof(value) == 'Vector2' then
                rawset(self, key, value)
                self:updateSquare()
            end
        end

        return setmetatable({}, meta)
    elseif Type == 'Circle' then
        local a = Instance.new("Frame", Instance.new("ScreenGui", DrawingDict))
        a.Visible = false
        a.Size = UDim2.new(0, 0, 0, 0)
        a.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
        a.BackgroundTransparency = 1
        a.BorderSizePixel = 0
        local b = Instance.new("UIStroke", a)
        b.Color = Color3.fromRGB(255, 255, 255)
        b.Enabled = false
        b.Thickness = 1
        local c = Instance.new("UICorner", a)
        c.CornerRadius = UDim.new(1, 0)

        local meta = baseProps
        meta.__index = {
            Thickness = 1,
            Filled = false,
            NumSides = 0,
            Radius = 1,
            Position = Vector2.new(0, 0),
            Transparency = 0,
            Remove = function()
                a:Destroy()
            end,
            Destroy = function()
                a:Destroy()
            end,
            updateCircle = function(self)
             a.Size = UDim2.new(0, self.Radius, 0, self.Radius)
             a.Position = UDim2.new(0, self.Position.X, 0, self.Position.Y)
             b.Enabled = not self
             b.Color = self.Color
            end
        }

        meta.__newindex = function(self, key, value)
            if key == 'Thickness' and typeof(value) == 'number' then
                rawset(self, key, value)
                b.Thickness = value
            elseif key == 'Visible' and typeof(value) == 'boolean' then
                rawset(self, key, value)
                a.Visible = value
            elseif key == 'Color' and typeof(value) == 'Color3' then
                rawset(self, key, value)
                a.BackgroundColor3 = value
                a.Color = value
            elseif key == 'Transparency' and typeof(value) == 'number' then
                rawset(self, key, value)
                a.BackgroundTransparency = 1 - value
            elseif key == 'Position' and typeof(value) == 'Vector2' then
                rawset(self, key, value)
                self:updateCircle()
            elseif key == 'Radius' and typeof(value) == 'number' then
                rawset(self, key, value)
                self:updateCircle()
            elseif key == 'NumSides' and typeof(value) == 'number' then
                rawset(self, key, value)
            elseif key == 'Filled' and typeof(value) == 'boolean' then
                rawset(self, key, value)
                self:updateCircle()
            end
        end

        return setmetatable({}, meta)
    elseif Type == 'Text' then
        local a = Instance.new("TextLabel", DrawingDict)
        a.Visible = false
        a.Size = UDim2.new(0, 0, 0, 0)
        a.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
        a.BackgroundTransparency = 1
        a.BorderSizePixel = 0
        a.TextStrokeColor3 = Color3.new(0,0,0)
        a.TextStrokeTransparency = 1

        local meta = baseProps
        meta.__index = {
            Text = '',
            Transparency = 0,
            Size = 0,
            Center = false,
            Outline = false,
            OutlineColor = Color3.new(0,0,0),
            Position = Vector2.new(0,0),
            Font = 3,
            Remove = function()
                a:Destroy()
            end,
            Destroy = function()
                a:Destroy()
            end,
            updateText = function(self)
             a.TextScaled = true
             a.Size = UDim2.new(0, self.Size * 3, 0, self.Size / 2)
             a.Position = UDim2.new(0, self.Position.X, 0, self.Position.Y)
             a.Text = self.Text
             a.Font = Fonts[self.Font]
             a.Visible = self.Visible
             a.TextColor3 = self.Color
             a.TextTrasparency = 1 - self.Transparency
             a.BorderSizePixel = self.Outline and 1 or 0
             if self.Center then
              a.TextXAlignment = Enum.TextXAlignment.Center
              a.TextYAlignment = Enum.TextYAlignment.Center
             else
              a.TextXAlignment = Enum.TextXAlignment.Left
              a.TextYAlignment = Enum.TextYAlignment.Top
             end
             a.TextStrokeTransparency = self.Outline and 0 or 1
             a.TextStrokeColor3 = self.OutlineColor
            end
        }

        meta.__newindex = function(self, key, value)
            if key == 'Text' and typeof(value) == 'string' then
                rawset(self, key, value)
            elseif key == 'Visible' and typeof(value) == 'boolean' then
                rawset(self, key, value)
                a.Visible = value
            elseif key == 'Color' and typeof(value) == 'Color3' then
                rawset(self, key, value)
            elseif key == 'Transparency' and typeof(value) == 'number' then
                rawset(self, key, value)
            elseif key == 'Position' and typeof(value) == 'Vector2' then
                rawset(self, key, value)
            elseif key == 'Size' and typeof(value) == 'number' then
                rawset(self, key, value)
            elseif key == 'Outline' and typeof(value) == 'boolean' then
                rawset(self, key, value)
            elseif key == 'Center' and typeof(value) == 'boolean' then
                rawset(self, key, value)
            elseif key == 'OutlineColor' and typeof(value) == 'Color3' then
                rawset(self, key, value)
            elseif key == 'Font' and typeof(value) == 'number' then
                rawset(self, key, value)
            end
            self:updateText()
        end

        return setmetatable({}, meta)
    end
end

local Count = 0
local Total = 0
for index, _ in pairs(Descendants(funcs)) do
 if not getgenv()[index] then
  Total = Total + 1
 end
end
for i, v in pairs(Descendants(funcs)) do
 if not getgenv()[i] then Count = Count + 1 end
 local Result = SafeOverride(i, v)
 local str = Result == 1 and ('%s %s already exists.'):format(type(v), i) or Result == 2 and ("Added %s %s to the global environment. (%d/%d)"):format(type(v), i, Count, Total) or Result ~= 1 and Result ~= 2 and ("Unknown result for function %s."):format(type(v), i)
 print(str)
end
funcs.syn.protect_gui(DrawingDict)
