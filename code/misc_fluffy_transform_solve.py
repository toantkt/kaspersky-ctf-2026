from __future__ import annotations

import argparse
import re

import numpy as np
import soundfile as sf
from scipy.signal import butter, sosfiltfilt


# Carrier frequencies recovered from the recording spectrum.
CARRIERS = (997.0, 2203.0, 4211.0)

# Signal/encoding parameters recovered from the waveform structure.
LOWPASS_HZ = 80.0
START_MS = 1000
SLOT_MS = 75
SLOT_COUNT = 267
PAYLOAD_OFFSET_SLOTS = 7
SAMPLE_MS = 1
MOVEMENT_THRESHOLD = 0.01

# Standard International Morse alphabet plus the underscore used by the flag.
MORSE = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    "-----": "0",
    "..--.-": "_",
}


def demodulate(audio: np.ndarray, sr: int, fc: float) -> np.ndarray:
    """Demodulate one carrier and low-pass its amplitude envelope."""
    t = np.arange(audio.size, dtype=np.float64) / sr
    mixed = audio * np.exp(-2j * np.pi * fc * t)
    sos = butter(
        8,
        LOWPASS_HZ / (sr / 2.0),
        btype="lowpass",
        output="sos",
    )
    return 2.0 * np.abs(sosfiltfilt(sos, mixed))


def recover_distances(audio: np.ndarray, sr: int) -> np.ndarray:
    """Recover the 3-D trajectory and return movement for each 1 ms step."""
    x = demodulate(audio, sr, CARRIERS[0])

    # A 50% duty-cycle square wave has fundamental amplitude 4/pi times its
    # square-wave amplitude, so undo the fundamental scaling.
    y = demodulate(audio, sr, CARRIERS[1]) * np.pi / 4.0

    # A unit-amplitude triangle wave has fundamental amplitude 8/pi^2 times
    # its triangle-wave amplitude, so undo that scaling as well.
    z = demodulate(audio, sr, CARRIERS[2]) * (np.pi**2) / 8.0

    sample_step = max(1, round(sr * SAMPLE_MS / 1000.0))
    coords = np.column_stack((x, y, z))[::sample_step]
    return np.linalg.norm(np.diff(coords, axis=0), axis=1)


def slot_distances(distance_per_ms: np.ndarray) -> np.ndarray:
    """Integrate travelled distance over each 75 ms slot."""
    slots = []
    for index in range(SLOT_COUNT):
        start = START_MS + index * SLOT_MS
        end = start + SLOT_MS
        if start >= distance_per_ms.size:
            raise ValueError("WAV is too short for the expected payload")
        slots.append(distance_per_ms[start:min(end, distance_per_ms.size)].sum())
    return np.asarray(slots, dtype=np.float64)


def distances_to_bits(slots: np.ndarray) -> np.ndarray:
    """Classify each slot as movement (1) or no movement (0)."""
    if slots.size != SLOT_COUNT:
        raise ValueError(f"Expected {SLOT_COUNT} slots, got {slots.size}")

    # The recovered slots form two clearly separated populations:
    # non-moving slots are below ~0.005, while moving slots are above ~0.025.
    # 0.01 therefore sits safely in the gap.
    bits = (slots > MOVEMENT_THRESHOLD).astype(np.uint8)

    # The first seven slots are synchronization/framing; payload begins at 7.
    return bits[PAYLOAD_OFFSET_SLOTS:]


def rle(bits: np.ndarray) -> list[tuple[int, int]]:
    """Run-length encode the bit stream."""
    if bits.size == 0:
        return []

    runs: list[tuple[int, int]] = []
    current = int(bits[0])
    length = 1

    for bit in bits[1:]:
        bit = int(bit)
        if bit == current:
            length += 1
        else:
            runs.append((current, length))
            current, length = bit, 1

    runs.append((current, length))
    return runs


def bits_to_morse(bits: np.ndarray) -> str:
    """Decode the movement-bit stream as timing-based Morse code."""
    symbols: list[str] = []
    current_symbol = ""

    for value, length in rle(bits):
        if value == 1:
            # Mark timing: 1 slot = dot, 3 slots = dash.
            if length not in (1, 3):
                raise ValueError(f"Unexpected mark length {length}")
            current_symbol += "." if length == 1 else "-"
            continue

        # Space timing: 1 = inside a character, 3 = next character,
        # >=7 = word separator.
        if length == 1:
            continue
        if length == 3:
            if not current_symbol:
                raise ValueError("Character separator without a Morse symbol")
            symbols.append(current_symbol)
            current_symbol = ""
        elif length >= 7:
            if current_symbol:
                symbols.append(current_symbol)
                current_symbol = ""
            symbols.append(" ")
        else:
            raise ValueError(f"Unexpected gap length {length}")

    if current_symbol:
        symbols.append(current_symbol)

    decoded: list[str] = []
    for symbol in symbols:
        if symbol == " ":
            decoded.append(" ")
        elif symbol in MORSE:
            decoded.append(MORSE[symbol])
        else:
            raise ValueError(f"Unknown Morse symbol: {symbol!r}")

    return "".join(decoded)


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve Kaspersky CTF 2026 Fluffy Transform")
    parser.add_argument("wav", help="challenge WAV file")
    args = parser.parse_args()

    audio, sr = sf.read(args.wav, dtype="float64")
    if audio.ndim != 1:
        raise ValueError("Expected a mono WAV")

    distance = recover_distances(audio, sr)
    slots = slot_distances(distance)
    bits = distances_to_bits(slots)
    text = bits_to_morse(bits).strip()

    print(f"[+] WAV: {sr} Hz, {audio.size} samples")
    print(f"[+] movement threshold: {MOVEMENT_THRESHOLD:.6f}")
    print(f"[+] recovered text: {text}")

    match = re.fullmatch(r"[A-Za-z0-9_]+", text)
    if not match:
        raise ValueError(f"Recovered text has unexpected characters: {text!r}")

    flag = f"kaspersky{{{match.group(0)}}}"
    print(f"[+] flag: {flag}")


if __name__ == "__main__":
    main()
