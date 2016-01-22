cmake_minimum_required(VERSION 2.8)

project(utf8cl LANGUAGES CXX C)

if (!MSVC)
	message(FATAL_ERROR "MSVC please")
endif()

add_definitions(-D_UNICODE)

#===================================================================================
#
# CMake compile with /MT instead of /MD
#
# http://stackoverflow.com/questions/14172856/cmake-compile-with-mt-instead-of-md
#
#===================================================================================

set(CompilerFlags
	CMAKE_CXX_FLAGS_DEBUG
	CMAKE_CXX_FLAGS_RELEASE
	CMAKE_CXX_FLAGS_RELWITHDEBINFO
	CMAKE_CXX_FLAGS_MINSIZEREL
	CMAKE_C_FLAGS_DEBUG
	CMAKE_C_FLAGS_RELEASE
	CMAKE_C_FLAGS_RELWITHDEBINFO
	CMAKE_C_FLAGS_MINSIZEREL
)

foreach(CompilerFlag ${CompilerFlags})
	string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()




#===================================================================================
#
# Detours Express 3.0
#
# http://research.microsoft.com/en-us/projects/detours/
#
#===================================================================================

set(detours_HEADERS
	third_party/detours/detours.h
	third_party/detours/detver.h
)

set(detours_SOURCES
	third_party/detours/creatwth.cpp
	third_party/detours/modules.cpp
)

if (CMAKE_CL_64)
	set(detours_DEFINES
		DETOURS_BITS=64
		DETOURS_X64=1
		DETOURS_64BIT=1
		DETOURS_OPTION_BITS=32
		_AMD64_
	)
else()
	set(detours_DEFINES
		DETOURS_BITS=32
		DETOURS_X86=1
		DETOURS_32BIT=1
		DETOURS_OPTION_BITS=64
		_X86_
	)
endif()

add_library(detours STATIC ${detours_HEADERS} ${detours_SOURCES})
target_include_directories(detours INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/detours>)
target_compile_definitions(detours PRIVATE ${detours_DEFINES})




#===================================================================================
#
# MinHook - The Minimalistic x86/x64 API Hooking Library
#
# http://www.codeproject.com/Articles/44326/MinHook-The-Minimalistic-x-x-API-Hooking-Libra
#
#===================================================================================

set(minhook_HEADERS
	third_party/minhook/include/MinHook.h
	third_party/minhook/src/buffer.h
	third_party/minhook/src/trampoline.h
	third_party/minhook/src/HDE/hde32.h
	third_party/minhook/src/HDE/hde64.h
	third_party/minhook/src/HDE/pstdint.h
	third_party/minhook/src/HDE/table32.h
	third_party/minhook/src/HDE/table64.h
)

set(minhook_SOURCES
	third_party/minhook/src/buffer.c
	third_party/minhook/src/hook.c
	third_party/minhook/src/trampoline.c
	third_party/minhook/src/HDE/hde32.c
	third_party/minhook/src/HDE/hde64.c
)

add_library(minhook STATIC ${minhook_HEADERS} ${minhook_SOURCES})
target_include_directories(minhook INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party/minhook/include>)




#===================================================================================
#
# utf8hook
#
#===================================================================================

if (CMAKE_CL_64)
	set(HOOK_BUILD_BITS 64)
else()
	set(HOOK_BUILD_BITS 32)
endif()

add_library(utf8hook SHARED src/utf8hook.cpp)
target_link_libraries(utf8hook detours minhook)
set_target_properties(utf8hook PROPERTIES
	LINK_FLAGS "/export:DetourFinishHelperProcess,@1,NONAME"
	OUTPUT_NAME "utf8hook${HOOK_BUILD_BITS}"
)




#===================================================================================
#
# utf8cl
#
#===================================================================================

add_executable(utf8cl WIN32 src/utf8cl.cpp)
target_compile_definitions(utf8cl PRIVATE $<$<STREQUAL:$<TARGET_PROPERTY:WIN32_EXECUTABLE>,${CMAKE_WIN32_EXECUTABLE}>:_CONSOLE>)
target_link_libraries(utf8cl detours)
add_dependencies(utf8cl utf8hook)
