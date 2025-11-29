# NanoLock

**NanoLock** is a minimalist, ultra-secure command-line tool for symmetric text encryption and decryption.

It combines **Argon2id** (for robust key derivation) and **Fernet** (AES-128-CBC + HMAC-SHA256) to provide state-of-the-art security in under 100 lines of code. Its shortness makes it **easily auditable**, you can read and verify the entire logic in a few minutes.

## Installation

```bash
pip install cryptography argon2-cffi
```

## Usage

Run the script and follow the prompts to Encrypt (E) or Decrypt (D):

```bash
python nanolock.py
```

## Configuration

By default, NanoLock is tuned for maximum security, using **1 GiB of RAM** for key derivation to thwart brute-force attacks. 

**Important:** If you are running this on a device with limited memory (e.g., Raspberry Pi, older laptop), you **must** edit `nanolock.py` and lower the `memory_cost`:

- **Default:** `1048576` (1 GiB)
- **Low Memory:** `524288` (512 MiB) or `262144` (256 MiB)
- **Very Low Memory:** `65536` (64 MiB)

## Why NanoLock?

- **Auditable:** No hidden backdoors, no bloat. Just pure, standard cryptography.
- **Secure:** Uses 2025 best practices (Argon2id + authenticated encryption).
- **Portable:** A single Python file you can trust and carry anywhere.
