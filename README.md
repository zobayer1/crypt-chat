# CSE 722 Assignment 1: Encrypted Messaging Application

A secure TCP messaging application with end-to-end encryption, supporting:

- RSA Public Key Exchange
- AES-256 Encrypted Messaging
- Wireshark Packet Verification

## Dependencies

- C++ 11 or higher
- CMake 3.20 or higher
- Libuuid-devel (`sudo dnf install libuuid-devel`)
- OpenSSL (`sudo dnf install openssl-devel`)

## Formatting and Styling

- Format using `clang-format`:
  ```bash
  clang-format -i src/*.cpp include/*.h
  ```

## Build Instructions

- Create a build directory:
  ```bash
  mkdir build
  cd build
  ```
- Run CMake to configure the project:
  ```bash
  cmake ..
  ```
- Build the project:
  ```bash
  make
  ```
- Run the executable with a port number (e.g., 8090):
  ```bash
  export PORT=8090
  ../bin/cse722 $PORT
  ```

## License

This work is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
