# SNOW vs. SNOW2: The Evolution of Whitespace Steganography

Matthew Kwan’s original **SNOW** (an acronym for *Steganographic Nature Of Whitespace*) was released in the late 1990s and became a classic piece of hacker culture. It famously noted that locating trailing whitespace in text is "like finding a polar bear in a snowstorm."

**SNOW2** is a modern Rust reimplementation that honors the spirit of the original tool while upgrading its architecture, cryptography, and steganalysis resistance to meet modern security standards.

## 1. Steganography: Density & Discretion

* **The Original (SNOW):** The original tool concealed data by appending sequences of up to 7 spaces interspersed with tabs. This provided a very low data density, allowing only about 3 bits of storage for every 8 columns of whitespace. 
* **The Modernization (SNOW2):** While SNOW2 retains a tribute `classic-trailing` mode (encoding a deterministic 1 bit per line), its primary innovation is the `websafe-zw` mode. By utilizing zero-width Unicode characters (`U+200B` for 0, `U+200C` for 1), SNOW2 achieves a massive **8 bits per line**. This allows practical payloads to survive copy-pasting across modern platforms without requiring massive carrier files.

## 2. Cryptography: ICE vs. The Fortress

* **The Original (SNOW):** Kwan utilized his own custom 64-bit private key block cipher called **ICE** (Information Concealment Engine). In SNOW, ICE operated in a 1-bit cipher-feedback (CFB) mode. While impressive for the 1990s, custom block ciphers are entirely vulnerable to modern cryptanalysis.
* **The Modernization (SNOW2):** SNOW2 replaces ICE with a military-grade, authenticated cryptographic stack. 
    * Passwords are hashed using **Argon2id** (with parameters bound by strict extraction limits to prevent memory-exhaustion DoS).
    * The master secret undergoes domain separation via **HKDF-SHA256** to generate independent inner and outer keys.
    * Encryption is handled by **XChaCha20-Poly1305** for robust Authenticated Encryption with Associated Data (AEAD).

## 3. Post-Quantum Readiness

* **The Original (SNOW):** Relied entirely on symmetric-key encryption via passwords.
* **The Modernization (SNOW2):** SNOW2 introduces an optional Post-Quantum Cryptography (PQC) layer. It supports hybrid encryption using **Kyber1024** for key encapsulation and **Dilithium5** for detached signatures, ensuring that intercepted carrier files cannot be decrypted by future quantum computers.

## 4. Defeating Steganalysis: Finding the Polar Bear

* **The Original (SNOW):** Relied purely on the invisibility of the characters. However, modern statistical analysis can easily detect the sudden boundary where a hidden message ends and normal text resumes.
* **The Modernization (SNOW2):** SNOW2 actively engineers steganalysis resistance directly into the v4 pipeline. 
    * Payloads are padded to **constant-size buckets** (multiples of 64 bytes) to mask the true message length.
    * An **outer AEAD layer** flattens the entropy of the bitstream, making it indistinguishable from uniform random noise.
    * Most importantly, SNOW2 **random-fills ALL remaining carrier lines** with zero-width noise. This completely destroys the statistical boundary between the message and the padding.

## 5. Architecture & Compression

* **The Original (SNOW):** Written in C, it utilized a rudimentary custom Huffman encoding table optimized specifically for English text to squeeze data into the margins.
* **The Modernization (SNOW2):** Written in memory-safe **Rust**, SNOW2 utilizes standard **Deflate compression**. Furthermore, the core library is compiled to **WebAssembly (WASM)**, allowing the full encryption and steganography pipeline to run entirely client-side in a web browser with zero server dependencies.
