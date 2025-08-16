cmake_minimum_required(VERSION 3.20)
project(cryptochat LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set output directories to PROJECT_SOURCE_DIR (root folder)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/lib)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

find_library(UUID_LIBRARY uuid REQUIRED)

add_subdirectory(src)

# Standard CMake installation (for deployment)
install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)
