# EclipseCode Encryption Tool 🔐

A C++ console-based encryption/decryption tool that supports multiple classical cipher algorithms, file I/O, basic steganography, and an admin logging system. Built as part of a systems programming / OOP assignment.

---

## What it does

You can use this to encrypt and decrypt text files using one of four ciphers. It also has a "trial mode" so you can test it out before going through the (simulated) subscription flow. There's a basic steganography feature that lets you hide a secret message inside an encrypted file too, which is kinda cool.

---

## Features

- **4 Cipher Algorithms:**
  - Caesar Cipher — shifts letters by a fixed amount
  - Vigenère Cipher — uses a repeating keyword for shifting
  - XOR Cipher — XORs each character with a key, outputs hex
  - Substitution Cipher — maps every letter to a user-defined 26-char key

- **File Encryption/Decryption** — reads from `test.txt`, writes encrypted output to `test_enc.txt`, decrypted to `test_dec.txt`

- **Steganography** — hides a secret message (up to 100 chars) inside the encrypted file using a `<hidden>` delimiter

- **Logging System** — logs every encrypt/decrypt action with a timestamp to `logs.txt`. Viewing logs requires an admin password.

- **Trial Mode** — lets you test two short messages (≤100 chars) before subscribing

- **Simulated Payment Flow** — collects card info and "processes" a payment (it's fake, don't worry)

---

## How to compile & run

Make sure you have g++ installed. C++14 or later should work fine.

```bash
g++ -std=c++14 -o eclipse Blackbox_EclipseCode___1_.cpp
./eclipse
```

On Windows (MinGW):
```bash
g++ -std=c++14 -o eclipse.exe Blackbox_EclipseCode___1_.cpp
eclipse.exe
```

---

## How to use

1. Run the program
2. Choose to try **trial mode** or skip straight to subscribing
3. Go through the payment screen (it's simulated — enter any valid-format card info)
4. In the main menu:
   - **Option 1** — Encrypts `test.txt` using your chosen cipher. You can also optionally embed a hidden message.
   - **Option 2** — Decrypts `test_enc.txt` and saves the output to `test_dec.txt`. Also extracts any hidden message if one exists.
   - **Option 3** — View logs (requires admin password: `admin123`)
   - **Option 4** — Exit

> **Note:** Make sure `test.txt` exists and has some content before encrypting, otherwise it'll just error out.

---

## File Structure

```
.
├── Blackbox_EclipseCode___1_.cpp   # main source file (everything's in here)
├── test.txt                         # input file to encrypt (you create this)
├── test_enc.txt                     # encrypted output (auto-generated)
├── test_dec.txt                     # decrypted output (auto-generated)
└── logs.txt                         # action log file (auto-generated)
```

---

## Class Overview

| Class | What it does |
|---|---|
| `Cipher` | Abstract base class for all ciphers |
| `CaesarCipher` | Caesar shift cipher |
| `VigenereCipher` | Vigenère keyword cipher |
| `XORCipher` | XOR + hex encoding cipher |
| `SubstitutionCipher` | Full 26-char substitution cipher |
| `FileHandler` | Reads/writes files |
| `Steganography` | Hides/extracts messages using a delimiter |
| `Logger` | Logs actions to file, admin-only log viewer |
| `ConfigManager` | Tracks which cipher is currently active |

---

## Known Issues / Limitations

- The admin password is hardcoded as `admin123` — yeah, not great, would fix with proper hashing in a real project
- Steganography uses a plain text `<hidden>` delimiter which is super easy to spot, it's more of a proof-of-concept
- The payment system is completely fake and doesn't actually do anything with the card info
- Everything is in one `.cpp` file — ideally this would be split into headers and separate source files
- XOR cipher output is hex, so decryption will fail if you try a different cipher than what you encrypted with (you have to remember which one you used)

---

## Requirements

- C++14 or later
- Any standard C++ compiler (g++, clang++, MSVC)
- No external libraries needed — everything is from the STL

---

## Author

Made for CSE OOP / Systems Programming course.
