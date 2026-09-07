# Kaspersky CTF 2026 Write-ups

Write-ups for **Kaspersky CTF 2026**, documenting the reasoning, techniques, commands, and mistakes behind each solved challenge.

## Challenge Index

| Challenge        | Category | Write-up                                          |
| ---------------- | -------- | ------------------------------------------------- |
| Fluffy Transform | Misc     | [Fluffy Transform](write-ups/fluffy_transform.md) |
| Sudokrypt        | Crypto   | [Sudokrypt](write-ups/sudokrypt.md)               |

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
├── write-ups/
│   ├── fluffy_transform.md
│   └── sudokrypt.md
│
├── LICENSE
│
└── README.md
```

## Write-up Format

The challenge write-ups follow the same structure:

* **Recon** - service enumeration, source-code review, and important observations.
* **Exploitation** — the complete attack path, including commands, payloads, algorithms, and relevant solver output.
* **Dead Ends** — approaches that looked promising but failed, including why they failed.
* **Flag / Finding** — the final result.
* **Tools Used** — software and libraries that were relevant to the solve.
* **Lessons Learned** — techniques worth remembering for future CTFs.
