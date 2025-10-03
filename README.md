# CryptChat

A secure TCP messaging application with end-to-end encryption, supporting:

- RSA-2048 Public Key Exchange
- AES-256 Shared Key Exchange
- End-to-end Encrypted Messaging

---

## Dependencies

- C++ 11 or higher
- CMake 3.20 or higher (`sudo dnf install cmake`)
- Libuuid-devel (`sudo dnf install libuuid libuuid-devel`)
- OpenSSL (`sudo dnf install openssl-devel`)

---

## Formatting and Styling

Format using `clang-format`:

```bash
clang-format -i src/*.cpp include/*.h
```

---

## Build Instructions

1. Create a build directory:
    ```bash
    mkdir -p build
    cd build
    ```

2. Run CMake to configure the project:
    ```bash
    cmake ..
    ```

3. Build the project:
    ```bash
    make
    ```

4. Run the executable with a port number (e.g., 8090):
    ```bash
    export PORT=8090
    ../bin/cryptchat $PORT
    ```

---

## Command Reference

| Command                  | Action                                                                 |
|--------------------------|------------------------------------------------------------------------|
| `:help`                  | Display the help menu.                                                 |
| `:connect <host:port>`   | Connect to a remote peer.                                              |
| `:disconnect`            | Terminate the current connection and clear all shared keys.            |
| `:exchange pub [new]`    | Exchange RSA public keys. Use “new” to regenerate keys.                |
| `:exchange aes`          | Generate and share a new AES-256 session key (requires RSA keys).      |
| `:quit`                  | Exit the application after performing cleanup.                         |
| `<message>`              | Send a plaintext/encrypted message (if session key exists).            |

---

## Protocol Message Formats

### Connection Establishment

**CONN**
```
TYPE:CONN
ID:<A's UUID>
NAME:<A's Username>
NONCE:<A's Nonce>
END
```

**CONN-ACK**
```
TYPE:CONN_ACK
ID:<B's UUID>
NAME:<B's Username>
REPLY_NONCE:<A's Nonce + 1>
END
```

---

### Plaintext Messaging

**PLAIN**
```
TYPE:PLAIN
ID:<Sender's UUID>
NONCE:<Sender's Nonce>
MSG:<Message Body>
END
```

---

### Public Key Exchange

**PUBKEY-OFFER**
```
TYPE:PUBKEY_OFFER
ID:<A's UUID>
NONCE:<A's Nonce>
PUBKEY:<A's RSA Public Key>
SIG:<Signature by A>
END
```

**PUBKEY-RESP**
```
TYPE:PUBKEY_RESP
ID:<B's UUID>
NONCE:<B's Nonce>
REPLY_NONCE:<A's Nonce>
PUBKEY:<B's RSA Public Key>
SIG:<Signature by B>
END
```

---

### Session Key Exchange

**SESSKEY-OFFER**
```
TYPE:SESSKEY_OFFER
ID:<A's UUID>
NONCE:<A's Nonce>
AESKEY:<AES-256 key encrypted with B's public key, base64>
SIG:<Signature by A>
END
```

**SESSKEY-RESP**
```
TYPE:SESSKEY_RESP
ID:<B's UUID>
NONCE:<B's Nonce>
REPLY_NONCE:<A's Nonce>
SIG:<Signature by B>
END
```

---

### Encrypted Messaging

**CIPHER**
```
TYPE:CIPHER
ID:<Sender's UUID>
NONCE:<Sender's Nonce>
CIPHER:<base64(IV || TAG || CIPHERTEXT)>
END
```

**CIPHERTEXT Structure:**
```
ID:<Sender's UUID>
NONCE:<Sender's Nonce>
MSG:<Plaintext Message>
```

---

### Control Messages

**BYE / REJECT / ERROR**
```
TYPE:<BYE/REJECT/ERROR>
NONCE:<Sender's Nonce>
REASON:<Reason (optional)>
END
```

---

## Usage Notes

- Public key exchange (`:exchange pub`) must precede AES key exchange.
- Messages are encrypted only after AES key exchange.
- Use `:disconnect` before switching peers.

---

## License

This work is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
