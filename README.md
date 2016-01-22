# utf8cl
UTF-8 without BOM support for MSVC

### Usage
utf8cl [executable] [[arg1] [arg2] ... [argN]]

### Example: start Visual Studio 2015 IDE
utf8cl "C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\IDE\devenv.exe"

### Example: start cmd.exe (then nmake, cl, etc.)
utf8cl cmd

### How it works
The utf8cl.exe starts the target application and injects utf8hook32.dll/utf8hook64.dll
into that process and every child processes.

The utf8hook(32/64).dll will modify behavour of MultiByteToWideChar when it is called
from inside CL.exe (Microsoft C/C++ Optimized Compiler) to handle UTF-8 without BOM
files correctly?

The utf8cl.exe uses detours(http://research.microsoft.com/en-us/projects/detours/) to inject DLL into processes.

The utf8hook(32/64).dll uses MinHook(http://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra) to hook APIs. It also depends on detours.

I've tested with msvc 2010, 2013, 2015 with platforms x86, amd64, x86_amd64 and amd64_x86.
