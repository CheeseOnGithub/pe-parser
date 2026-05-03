cmake_minimum_required(VERSION 3.20)
project(peparser)

include(FetchContent) 
set(CMAKE_CXX_STANDARD 20)

add_executable(peparser
    src/main.cpp
    src/mappedfile.cpp
    src/parser.cpp
)

FetchContent_Declare(ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/ftxui
    GIT_TAG v6.1.9
)

FetchContent_MakeAvailable(ftxui)

target_link_libraries(peparser PRIVATE
    ftxui::component
    ftxui::dom
    ftxui::screen
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)