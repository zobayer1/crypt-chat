set(SRC_FILES
        main.c
        network.c
        crypto.c
        protocol.c
        session.c
)

add_executable(${PROJECT_NAME} ${SRC_FILES})

target_include_directories(${PROJECT_NAME}
        PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME}
        PRIVATE
        Threads::Threads
        OpenSSL::Crypto
        ${UUID_LIBRARY}
)

target_compile_options(${PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror=implicit-function-declaration
)
