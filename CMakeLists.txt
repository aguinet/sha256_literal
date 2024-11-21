cmake_minimum_required(VERSION 3.10)

project(sha256_literal)

include(CBuildKit)

option(USE_STATIC_LINKING "Use static linking for the runtime" ON)

if (USE_STATIC_LINKING)
    if (MSVC)
        # MSVC specific static linking flag
        add_compile_options(/MT$<$<CONFIG:Debug>:d>)
    else()
        # GCC/Clang specific static linking flag
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()

add_library_ns(sha256_literal sha256_literal STATIC sha256.cpp)
target_include_dir_iface(sha256_literal-sha256_literal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include include)
install_target_and_headers(sha256_literal sha256_literal)

add_executable(example example.cpp)
target_link_libraries(example sha256_literal::sha256_literal)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include)

install_cfgpkg(sha256_literal 
"include(\${CMAKE_CURRENT_LIST_DIR}/sha256_literal-sha256_literal-targets.cmake)
")