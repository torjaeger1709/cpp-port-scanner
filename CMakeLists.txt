cmake_minimum_required(VERSION 3.15)
project(PortScanner VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Core Backend Network Engines (MVC Model)
set(CORE_SOURCES
    src/cli_parser.cpp
    src/target_helper.cpp
    src/scanner_engine.cpp
    src/report_generator.cpp
    src/thread_pool.cpp
    src/raw_socket.cpp
)

# 1. CLI Executable Target
add_executable(port_scanner src/main.cpp ${CORE_SOURCES})
target_include_directories(port_scanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(WIN32)
    target_link_libraries(port_scanner PRIVATE ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(port_scanner PRIVATE Threads::Threads)
endif()

# 2. Desktop GUI Companion Target (Dear ImGui MVC on Windows)
if(WIN32)
    include(FetchContent)
    FetchContent_Declare(
        imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG v1.90.1
    )
    FetchContent_MakeAvailable(imgui)

    add_executable(port_scanner_gui
        src/gui_main.cpp
        src/gui_view.cpp
        src/scan_controller.cpp
        ${CORE_SOURCES}
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
    )

    target_include_directories(port_scanner_gui PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
    )

    target_link_libraries(port_scanner_gui PRIVATE ws2_32 d3d11 d3dcompiler dwmapi)
endif()
