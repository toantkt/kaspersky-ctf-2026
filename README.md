![CTF](https://img.shields.io/badge/CTF-Kaspersky%20CTF%202026-red)
![Writeups](https://img.shields.io/badge/Writeups-2-blue)

# Kaspersky CTF 2026 Writeups

Writeups for **Kaspersky CTF 2026**, documenting the reasoning, techniques, commands, and mistakes behind each solved challenge.

## Table of Contents

- [Kaspersky CTF 2026 Writeups](#kaspersky-ctf-2026-writeups)
  - [Table of Contents](#table-of-contents)
  - [Challenge Index](#challenge-index)
  - [Repository Structure](#repository-structure)
  - [Writeup Format](#writeup-format)

## Challenge Index

| Challenge        | Category | Writeup                                         |
| ---------------- | -------- | ----------------------------------------------- |
| Fluffy Transform | Misc     | [Fluffy Transform](writeup/fluffy_transform.md) |
| Sudokrypt        | Crypto   | [Sudokrypt](writeup/sudokrypt.md)               |

## Repository Structure

```text
kaspersky-ctf-2026/
│
├── code/
│   ├── crypto_sudokrypt_solve.py
│   └── misc_fluffy_transform_solve.py
│
├── img/
│   ├── crypto_sudokrypt.png
│   └── misc_fluffy_transform.png
│
├── resource/
│   ├── challenge_f25cea1608c1e224.wav
│   └── sudocrypt_08ec969ff2e58b97.tar.gz
│
├── writeup/
│   ├── fluffy_transform.md
│   └── sudokrypt.md
│
├── LICENSE
│
└── README.md
```

## Writeup Format

The challenge writeups follow the same structure:

- **Recon** - service enumeration, source-code review, and important observations.
- **Exploitation** — the complete attack path, including commands, payloads, algorithms, and relevant solver output.
- **Dead Ends** — approaches that looked promising but failed, including why they failed.
- **Flag / Finding** — the final result.
- **Tools Used** — software and libraries that were relevant to the solve.
- **Lessons Learned** — techniques worth remembering for future CTFs.
