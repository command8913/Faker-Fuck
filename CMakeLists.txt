cmake_minimum_required(VERSION 3.10)
project(fakerfuck)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fakerfuck main.cpp)

if(WIN32)
    target_compile_definitions(fakerfuck PRIVATE _WIN32_WINNT=0x0501 WINVER=0x0501)
endif()

if(MINGW OR MSYS)
    set_target_properties(fakerfuck PROPERTIES
            LINK_SEARCH_START_STATIC ON
            LINK_SEARCH_END_STATIC ON
    )

    target_link_options(fakerfuck PRIVATE
            -static
            -static-libgcc
            -static-libstdc++
    )


    target_link_libraries(fakerfuck PRIVATE
            winpthread
            iphlpapi
            psapi
            ws2_32
            advapi32
            psapi iphlpapi ws2_32 advapi32 urlmon
    )
elseif(MSVC)
    target_link_libraries(fakerfuck PRIVATE
            iphlpapi
            psapi
            ws2_32
            advapi32
    )
endif()
if(MSVC)
    target_compile_definitions(fakerfuck PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()