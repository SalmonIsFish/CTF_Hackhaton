# Crypto

## Overview

Crypto CTF challenges are puzzles about how information is represented, protected, hidden, or transformed. They often involve messages that look unreadable at first, such as long strings of symbols, numbers, hashes, or encoded text. The goal is usually to recognize the type of transformation and reason your way back to the original message or clue.

In beginner CTFs, crypto challenges often focus on foundations like [[Encoding]], [[Encryption]], [[Hashing]], [[Base64]], [[Hexadecimal]], [[ROT13]], [[Caesar Cipher]], and simple [[XOR]]. More advanced challenges may introduce real cryptographic systems such as [[AES]] and [[RSA]], but the learning goal is still educational: understand the idea, the assumptions, and the common mistakes that make a puzzle solvable.

Crypto challenges reward patience and careful observation. A useful beginner habit is to ask what kind of data you are looking at, whether it has a recognizable alphabet or format, and whether it may have been transformed more than once. This note does not provide attack instructions; it focuses on safe learning and CTF-style pattern recognition.

## Key Concepts

### [[Encoding]]

[[Encoding]] is a way to represent data in a different format so computers or people can store, send, or display it more easily. Encoding is not meant to be secret. For example, text can be represented as [[Base64]], [[Hexadecimal]], binary, URL encoding, or ASCII numbers. In CTFs, encoded data may look mysterious, but it is often just the same information written in another form. A key beginner idea is that encoding is reversible when you know the format. If a string has unusual characters, repeated patterns, or a familiar ending, it may be encoded rather than encrypted. Encoding is common in web data, files, scripts, and challenge descriptions. Learning common encodings helps you quickly recognize when a message only needs conversion.

### [[Encryption]]

[[Encryption]] is used to protect information by turning readable data into unreadable data using a key. Unlike [[Encoding]], encryption is intended to keep the message secret from people who do not have the correct key. Good encryption should not be reversible by simple guessing or formatting tricks. In CTFs, encryption challenges may use older ciphers, simplified systems, or intentionally weak settings so learners can understand important ideas. Examples include [[Caesar Cipher]], [[XOR]], [[AES]], and [[RSA]]. Beginners should focus on the relationship between plaintext, ciphertext, algorithms, and keys. Encryption is not magic; it follows rules. A challenge often gives clues about which rule was used, what key might matter, or what assumption was unsafe.

### [[Hashing]]

[[Hashing]] turns data into a fixed-size value called a hash or digest. It is designed to work in one direction: the same input should produce the same hash, but the hash should not easily reveal the original input. Hashes are used for integrity checks, password storage, file identification, and comparisons. In CTFs, hashes such as [[MD5]], [[SHA-1]], and [[SHA-256]] may appear as long strings of hexadecimal characters. A beginner should understand that hashing is different from [[Encryption]] because there is normally no decryption key. Some hashes are considered weak for modern security, especially when used with predictable or simple inputs. CTFs may use hashes to teach recognition, safe password storage ideas, and the limits of old algorithms.

### [[Base64]]

[[Base64]] is an encoding method that represents binary data using readable characters such as letters, numbers, plus signs, slashes, and sometimes equals signs at the end. It is commonly used when data needs to travel through systems that expect text, such as email, web forms, JSON, or configuration files. Base64 is not encryption and does not provide secrecy. In CTFs, Base64 often appears as a long string that may end with `=` or `==`. Beginners should recognize it as a common first thing to inspect when text looks encoded. Sometimes a challenge may use Base64 more than once or combine it with other encodings. The safe lesson is simple: Base64 changes representation, not meaning or security.

### [[Hexadecimal]]

[[Hexadecimal]], often called hex, is a base-16 number system using digits `0-9` and letters `a-f`. Computers store data as bytes, and hex is a compact way to write those bytes. For example, text, file contents, colors, memory values, and hashes can all be represented in hexadecimal. In CTFs, hex strings often look like long sequences of characters such as `48656c6c6f`. Beginners should learn that every two hex characters usually represent one byte. Hexadecimal is common in [[Hashing]], file signatures, encoded messages, and cryptographic values. Like [[Base64]], hex is not secret by itself. It is a representation. Recognizing hex helps you decide whether a string might need decoding, conversion to text, or comparison with another value.

### [[ROT13]]

[[ROT13]] is a simple letter substitution that shifts each letter by 13 places in the alphabet. Since the English alphabet has 26 letters, applying ROT13 twice returns the original text. It is not secure encryption, but it is a classic beginner puzzle format. In CTFs, ROT13 may appear when a message still looks like letters and words, but the words are unreadable. For example, punctuation and numbers may stay the same while letters are changed. Beginners should view ROT13 as a simple transformation rather than real cryptography. It is useful for learning the idea of substitution ciphers and pattern recognition. ROT13 also helps show why old or simple ciphers are not suitable for protecting sensitive information.

### [[Caesar Cipher]]

[[Caesar Cipher]] is a simple substitution cipher where each letter is shifted by a fixed number of positions in the alphabet. [[ROT13]] is a special case of the Caesar Cipher with a shift of 13. In CTFs, Caesar Cipher challenges are common for beginners because the idea is easy to understand and the result still keeps letter patterns. For example, repeated letters and word lengths remain visible even when the text is shifted. A beginner should know that Caesar Cipher is not secure for real protection because there are only a small number of possible shifts. Its value in CTFs is educational: it teaches how substitution works, how patterns survive transformations, and why modern [[Encryption]] needs much stronger design.

### [[XOR]]

[[XOR]] is a logical operation that compares bits. It is useful in computing and appears in many cryptographic ideas. One important property is that applying XOR with the same value twice can recover the original data. In CTFs, XOR may appear in beginner-friendly puzzles where text has been combined with a single byte, a short repeating key, or another known pattern. The result may look like random bytes or strange characters. Beginners do not need deep mathematics at first; the key idea is that XOR mixes data with another value in a reversible way when the correct value is known. XOR is not automatically secure on its own. Its safety depends heavily on how keys are generated and used.

### [[AES]]

[[AES]], or Advanced Encryption Standard, is a modern symmetric encryption algorithm. Symmetric means the same secret key is used to encrypt and decrypt data. AES is widely used in real systems when implemented correctly with safe modes, random initialization values where needed, and proper key handling. In CTFs, AES may appear in simplified examples to teach the difference between strong algorithms and weak usage. A challenge might focus on recognizing encrypted data, understanding block sizes, or noticing unsafe assumptions in a controlled setting. Beginners should not think of AES itself as weak. The important lesson is that even strong cryptography can be used incorrectly. Secure systems require sound algorithms, correct modes, careful randomness, and protected keys.

### [[RSA]]

[[RSA]] is a public-key cryptographic system. Unlike symmetric systems such as [[AES]], RSA uses a pair of related keys: a [[Public Key]] and a [[Private Key]]. The public key can be shared, while the private key must be protected. RSA is based on number theory and is commonly used for encryption of small values, digital signatures, and key exchange designs in larger systems. In CTFs, RSA challenges often teach concepts such as key pairs, modular arithmetic, padding, and why parameter choices matter. Beginners should focus on the high-level idea first: public-key cryptography lets people communicate or verify information without sharing one secret key in advance. Correct implementation and safe parameters are essential for real security.

### [[MD5]]

[[MD5]] is an older hash function that produces a 128-bit hash, often written as 32 hexadecimal characters. It was once widely used for checksums and data comparison, but it is no longer considered safe for many security purposes because weaknesses have been found. In CTFs, MD5 is common because it is recognizable and useful for teaching the history and limitations of [[Hashing]]. Beginners may see MD5 values in challenges involving file checks, password-like strings, or integrity clues. The key idea is that MD5 is a hash, not encryption. It is one-way in design, but its weaknesses and speed make it unsuitable for modern password protection or collision-resistant security. Modern systems should use stronger designs.

### [[SHA-1]]

[[SHA-1]] is another older hash function. It produces a 160-bit hash, usually shown as 40 hexadecimal characters. Like [[MD5]], SHA-1 was used widely in the past but is now considered unsafe for collision-resistant security because practical weaknesses have been demonstrated. In CTFs, SHA-1 may appear because it is easy to identify and helps learners compare different hash formats. Beginners should learn to recognize the length and style of SHA-1 digests, while also understanding that hash length alone does not make an algorithm safe. SHA-1 is part of cryptography history, but modern applications should avoid it for security-sensitive purposes. It is useful in CTFs mainly as a teaching example.

### [[SHA-256]]

[[SHA-256]] is a member of the SHA-2 family of hash functions. It produces a 256-bit hash, commonly shown as 64 hexadecimal characters. SHA-256 is widely used in modern systems for integrity checks, digital signatures, certificates, and many security designs. In CTFs, SHA-256 may appear as a file hash, message digest, or clue that needs to be recognized. Beginners should understand that SHA-256 is a one-way hash, not an encryption method. It is stronger than [[MD5]] and [[SHA-1]] for modern security uses, but how it is used still matters. For example, password storage requires more than simply hashing a password once. The main lesson is to identify the hash type and understand its purpose.

### [[Frequency Analysis]]

[[Frequency Analysis]] is a method of studying how often letters, symbols, or patterns appear in text. In natural language, some letters appear more often than others. For example, English commonly uses letters like `e`, `t`, and `a`. Simple substitution ciphers may preserve these patterns, making them easier to reason about. In CTFs, frequency analysis can help with older ciphers or puzzle ciphers where the same plaintext symbol always maps to the same ciphertext symbol. Beginners should see it as a clue-finding technique, not a guaranteed solution. It works best when there is enough text to reveal patterns. Frequency analysis teaches an important crypto idea: even when text is disguised, patterns can leak information.

### [[Public Key]]

A [[Public Key]] is part of public-key cryptography. It is designed to be shared with others. Depending on the system, a public key may let people encrypt messages to the key owner or verify signatures made by the matching [[Private Key]]. Public keys are used in systems such as [[RSA]], certificates, secure websites, and software signing. In CTFs, a public key may be provided as part of a challenge so learners can identify the algorithm, inspect metadata, or understand how the key pair is supposed to work. Beginners should remember that "public" does not mean unimportant. A public key must still be authentic, because trusting the wrong public key can break the security goal of the system.

### [[Private Key]]

A [[Private Key]] is the secret part of a public-key pair. It must be protected because it can decrypt data meant for the owner or create signatures that prove ownership, depending on the system. In [[RSA]], the private key is mathematically related to the [[Public Key]], but it should not be possible to derive the private key from a properly generated public key. In CTFs, private keys may appear as files, clues, or intentionally exposed artifacts in a lab environment. Beginners should treat private keys as sensitive material in real life. The defensive lesson is that keys need safe storage, correct permissions, strong generation, and careful handling. Losing a private key can break the trust of the whole system.

## Common Public Tools

### [[CyberChef]]

- Purpose: [[CyberChef]] is a web-based tool for transforming data through operations such as encoding, decoding, compression, hashing, and formatting.
- Typical CTF usage: It is commonly used to inspect [[Base64]], [[Hexadecimal]], ROT-style text, layered encodings, timestamps, and unusual strings.
- Beginner tips: Try one transformation at a time and read the output carefully. If the result still looks encoded, it may have multiple layers. CyberChef is powerful, but observation matters more than clicking random operations.

### [[OpenSSL]]

- Purpose: [[OpenSSL]] is a command-line toolkit and library for cryptographic operations, certificates, keys, hashes, and encrypted data formats.
- Typical CTF usage: It is often used to inspect certificate files, identify key formats, compute hashes, and understand standard crypto file structures in lab challenges.
- Beginner tips: Start by using it to view information rather than change data. Pay attention to file extensions, headers, and whether something looks like a certificate, [[Public Key]], [[Private Key]], or encrypted blob.

### [[Hashcat]]

- Purpose: [[Hashcat]] is a password recovery and hash analysis tool used in authorized testing and research.
- Typical CTF usage: It may appear in challenges involving weak or intentionally simple hashes, especially when the challenge is designed around learning password storage weaknesses.
- Beginner tips: Use it only in legal lab environments. First identify the hash type and understand what the challenge is teaching. Remember that strong passwords and modern password hashing methods are designed to resist this kind of analysis.

### [[John the Ripper]]

- Purpose: [[John the Ripper]] is a password auditing and recovery tool used for authorized security testing.
- Typical CTF usage: It is commonly used in CTFs with intentionally weak password hashes, protected archive files, or educational password-cracking examples.
- Beginner tips: Focus on the format of the data before using the tool. Many beginner mistakes come from feeding the wrong format into a tool and misunderstanding the result. Keep usage limited to CTF files and systems where you have permission.

### [[dcode.fr]]

- Purpose: [[dcode.fr]] is an online collection of tools for codes, ciphers, encodings, math puzzles, and classical cryptography.
- Typical CTF usage: It is useful for learning and checking classical ciphers such as [[Caesar Cipher]], [[ROT13]], substitution ciphers, and frequency-based puzzles.
- Beginner tips: Use it as a learning aid, not a replacement for understanding. Read the explanation for each cipher and compare the output with your own observations. This helps you build recognition skills for future challenges.

## Where Flags Usually Hide

In beginner crypto CTFs, flags often hide inside text that has been transformed. The most common first clue is encoded text. A string may look unreadable, but it could be [[Base64]], [[Hexadecimal]], binary, or another simple representation. Hidden strings may also appear inside files, metadata, source code, or challenge descriptions. Careful reading often matters as much as tool use.

Flags may also be hidden behind weak hashes in educational challenges. This usually teaches why simple or predictable inputs are unsafe with fast hash functions such as [[MD5]] or [[SHA-1]]. Some puzzles use multiple encoding layers, where decoded output becomes the input for another decoding step. Others use simple ciphers such as [[ROT13]], [[Caesar Cipher]], or basic [[XOR]] to teach pattern recognition.

ZIP passwords sometimes appear in beginner challenges as part of a larger puzzle. The password may be hinted by nearby text, filenames, metadata, or another solved step. The safe approach is to treat the archive as a CTF artifact and look for intended clues. Do not apply these ideas to files or systems that are not part of a legal learning environment.

## Beginner Study Links

### picoCTF

[picoCTF](https://picoctf.org/) is a beginner-friendly CTF platform with many introductory crypto challenges. It is useful for practicing recognition of encodings, simple ciphers, hashes, and basic problem-solving habits. The challenges are designed for learning, so beginners can build confidence gradually.

### CryptoHack

[CryptoHack](https://cryptohack.org/) is a learning platform focused specifically on cryptography. It covers topics from basic encodings and XOR to number theory, RSA, elliptic curves, and modern cryptographic ideas. Beginners can start with the early modules and grow into more advanced concepts over time.

### OverTheWire

[OverTheWire](https://overthewire.org/wargames/) provides wargames that build general security and command-line skills. While it is not only about crypto, it helps beginners become comfortable with files, terminals, strings, encodings, and careful step-by-step reasoning. These skills transfer well to crypto CTF challenges.

### TryHackMe

[TryHackMe](https://tryhackme.com/) offers guided rooms and learning paths for cybersecurity topics, including cryptography basics. It is helpful for learners who prefer structured explanations and practical exercises. Beginner rooms can introduce encodings, hashes, classical ciphers, and the safe use of common tools.

## Related Notes

- [[Encoding]]
- [[Encryption]]
- [[Hashing]]
- [[Base64]]
- [[Hexadecimal]]
- [[ROT13]]
- [[Caesar Cipher]]
- [[XOR]]
- [[AES]]
- [[RSA]]
- [[MD5]]
- [[SHA-1]]
- [[SHA-256]]
- [[Frequency Analysis]]
- [[Public Key]]
- [[Private Key]]
- [[CyberChef]]
- [[OpenSSL]]
- [[Hashcat]]
- [[John the Ripper]]
- [[dcode.fr]]
