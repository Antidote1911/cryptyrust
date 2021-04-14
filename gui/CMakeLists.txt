cmake_minimum_required(VERSION 3.5)

project(cryptyrust LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        droparea.cpp
        adapter.cpp
        droparea.h
        adapter.h
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(cryptyrust
        ${PROJECT_SOURCES}
    )
else()
    if(ANDROID)
        add_library(cryptyrust SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(cryptyrust
            ${PROJECT_SOURCES}
        )
    endif()
endif()

if (WIN32)
    target_link_libraries(cryptyrust PRIVATE Qt${QT_VERSION_MAJOR}::Widgets advapi32 user32 ws2_32 pthread dl ${CMAKE_CURRENT_SOURCE_DIR}/../target/release/cryptyrust_adapter.lib)
    
endif (WIN32)

if (UNIX)
    target_link_libraries(cryptyrust PRIVATE Qt${QT_VERSION_MAJOR}::Widgets dl ${CMAKE_CURRENT_SOURCE_DIR}/../target/release/libcryptyrust_adapter.a)
endif (UNIX)


if(UNIX AND NOT APPLE)
        set(LINUX TRUE)
endif()
if(LINUX)    # if(NOT LINUX) should work, too, if you need that
    message(STATUS ">>> Linux")
    # linux stuff here
else()
    message(STATUS ">>> Not Linux")
        # stuff that should happen not on Linux
endif()
