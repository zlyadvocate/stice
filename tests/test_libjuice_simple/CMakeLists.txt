cmake_minimum_required(VERSION 3.10)
project(test_libjuice_simple)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 添加 libjuice 子目录
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../libjuice ${CMAKE_CURRENT_BINARY_DIR}/libjuice)

# 创建测试可执行文件
add_executable(test_libjuice_simple test_libjuice_simple.cpp)

# 链接 libjuice
target_link_libraries(test_libjuice_simple PRIVATE juice)

# 设置包含目录
target_include_directories(test_libjuice_simple PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../libjuice/include)

# Windows 特定设置
if(WIN32)
    target_link_libraries(test_libjuice_simple PRIVATE ws2_32)
    if(MSVC)
        target_compile_options(test_libjuice_simple PRIVATE /W4)
    else()
        target_compile_options(test_libjuice_simple PRIVATE -Wall -Wextra)
    endif()
else()
    target_link_libraries(test_libjuice_simple PRIVATE pthread)
    target_compile_options(test_libjuice_simple PRIVATE -Wall -Wextra)
endif()

# 双 agent 带宽测试
add_executable(test_libjuice_bench test_libjuice_bench.c)
target_link_libraries(test_libjuice_bench PRIVATE juice)
target_include_directories(test_libjuice_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../libjuice/include)
if(WIN32)
    target_link_libraries(test_libjuice_bench PRIVATE ws2_32)
else()
    target_link_libraries(test_libjuice_bench PRIVATE pthread)
endif()
