import re
import socket

from sudokrypt_core import (
    FIELD,
    GENERATOR,
    SBOX,
    BLOCK_SIZE,
    diffuse_words,
    undiffuse_words,
    public_wrapper_inv,
    split_word,
    rotl4,
    rotl16,
    block_rotation,
)

HOST = "tcp.sasc.tf"
PORT = 31415

QUERIES = 96
ORDER = 56


# ------------------------------------------------------------
# Finite-field helpers
# ------------------------------------------------------------

def gauss_solve(A, b, p=FIELD):
    """
    Solve A*x=b over GF(p).
    A may be rectangular. Requires full column rank.
    """
    m = len(A)
    n = len(A[0])

    a = [
        [x % p for x in row] + [b[i] % p]
        for i, row in enumerate(A)
    ]

    row = 0
    pivots = []

    for col in range(n):
        pivot = None
        for r in range(row, m):
            if a[r][col]:
                pivot = r
                break

        if pivot is None:
            continue

        a[row], a[pivot] = a[pivot], a[row]

        inv = pow(a[row][col], p - 2, p)
        for j in range(col, n + 1):
            a[row][j] = a[row][j] * inv % p

        for r in range(m):
            if r == row or not a[r][col]:
                continue

            factor = a[r][col]
            for j in range(col, n + 1):
                a[r][j] = (a[r][j] - factor * a[row][j]) % p

        pivots.append(col)
        row += 1

        if row == m:
            break

    for r in range(row, m):
        if all(a[r][c] == 0 for c in range(n)) and a[r][n]:
            raise RuntimeError("inconsistent linear system")

    if len(pivots) != n:
        raise RuntimeError(
            f"linear system has rank {len(pivots)}, expected {n}"
        )

    x = [0] * n
    for r, col in enumerate(pivots):
        x[col] = a[r][n]

    return x


# ------------------------------------------------------------
# Ciphertext inversion
# ------------------------------------------------------------

def undo_outer_ciphertext(ct):
    assert len(ct) == 32

    words = [
        int.from_bytes(ct[i:i + 2], "big")
        for i in range(0, 32, 2)
    ]

    # inverse of diffuse_words()
    words = undiffuse_words(words)

    # inverse public_wrapper(), rank is important
    words = [
        public_wrapper_inv(word, rank)
        for rank, word in enumerate(words)
    ]

    return words


def candidate_stream(word, symbol_inv_zero, q):
    """
    Plaintext is chosen so symbol == 0.

    Given the recovered inner word, try every possible low nibble
    of the stream value. For each low nibble the rest of the
    stream value follows deterministically.
    """
    _, row_field, col_field, check_field = split_word(word)

    result = []

    for low in range(16):
        row_code = SBOX[low]

        base_col = (symbol_inv_zero - row_code) & 15
        mask = (row_field - row_code) & 15

        expected_col = (base_col + 2 * mask) & 15
        if expected_col != col_field:
            continue

        high = (
            check_field
            ^ SBOX[
                (
                    row_code
                    ^ rotl4(base_col, 1)
                    ^ q
                    ^ low
                ) & 15
            ]
        )

        stream_value = (
            (high << 8)
            | (mask << 4)
            | low
        )

        result.append(stream_value)

    if len(result) != 1:
        raise RuntimeError(
            f"expected one stream candidate, got {len(result)}"
        )

    return result[0]


def block_options(ct, block_number, symbol_inv_zero):
    """
    Return all possible interpretations of a block.

    Plaintext = 00 11 22 ... ff

    Therefore:
        q       = original byte index
        symbol  = 0

    ranked[r] corresponds to original index:
        (r + rotation) & 15

    The q-label permutation is fixed for the entire session.
    """
    ranked = undo_outer_ciphertext(ct)
    options = []

    for rotation in range(16):
        streams = [0] * 16
        qmap = [0] * 16

        for rank, word in enumerate(ranked):
            original_index = (rank + rotation) & 15

            q = original_index

            streams[original_index] = candidate_stream(
                word,
                symbol_inv_zero,
                q,
            )

            qmap[original_index] = word >> 12

        # The rotation is itself encoded by the stream.
        if block_rotation(streams, block_number) != rotation:
            continue

        options.append(
            (
                rotation,
                tuple(qmap),
                streams,
            )
        )

    return options


# ------------------------------------------------------------
# Recover all 96 stream blocks
# ------------------------------------------------------------

def recover_stream(ciphertexts):
    """
    Simultaneously determine:

        symbol_inv[0]
        q_perm
        rotation for every block
        all 16 stream lanes

    q_perm consistency is what resolves the remaining ambiguity.
    """

    states = []

    # symbol_inv[0] is only 4 bits.
    for c in range(16):
        for rotation, qmap, streams in block_options(
            ciphertexts[0],
            0,
            c,
        ):
            states.append(
                {
                    "c": c,
                    "qmap": qmap,
                    "rotations": [rotation],
                    "streams": [streams],
                }
            )

    for block_number in range(1, len(ciphertexts)):
        new_states = []

        for state in states:
            options = block_options(
                ciphertexts[block_number],
                block_number,
                state["c"],
            )

            for rotation, qmap, streams in options:
                if qmap != state["qmap"]:
                    continue

                new_states.append(
                    {
                        "c": state["c"],
                        "qmap": state["qmap"],
                        "rotations": (
                            state["rotations"] + [rotation]
                        ),
                        "streams": (
                            state["streams"] + [streams]
                        ),
                    }
                )

        states = new_states

        if not states:
            raise RuntimeError(
                f"no consistent state after block {block_number}"
            )

        print(
            f"[+] block {block_number + 1:2d}/96: "
            f"{len(states)} candidate state(s)"
        )

    if len(states) != 1:
        raise RuntimeError(
            f"expected one complete state, got {len(states)}"
        )

    return states[0]


# ------------------------------------------------------------
# Recover common spectral nodes
# ------------------------------------------------------------

def recover_recurrence(streams):
    """
    For each lane:

        s[t] = sum_j c[j] * n[j]^t

    There are 56 common nodes, so every lane satisfies the
    same order-56 recurrence:

        s[t+56] = r[0]s[t] + ... + r[55]s[t+55]

    We have 16 * 40 = 640 equations for only 56 unknowns.
    """

    A = []
    b = []

    for lane in range(16):
        sequence = [
            streams[t][lane]
            for t in range(96)
        ]

        for t in range(96 - ORDER):
            A.append([
                sequence[t + i]
                for i in range(ORDER)
            ])
            b.append(sequence[t + ORDER])

    print("[+] solving common order-56 recurrence...")
    recurrence = gauss_solve(A, b)

    return recurrence


def polynomial_value(x, recurrence):
    """
    P(x) = x^56 - sum_i recurrence[i] x^i
    """
    p = FIELD

    value = pow(x, ORDER, p)
    xp = 1

    for r in recurrence:
        value = (value - r * xp) % p
        xp = xp * x % p

    return value


def recover_nodes(recurrence):
    """
    Nodes are guaranteed to be powers of GENERATOR, with exponent
    in 1..FIELD-2. Search the complete multiplicative group.
    """
    nodes = []

    x = GENERATOR

    for _ in range(1, FIELD - 1):
        if polynomial_value(x, recurrence) == 0:
            nodes.append(x)

        x = x * GENERATOR % FIELD

    nodes.sort()

    if len(nodes) != ORDER:
        raise RuntimeError(
            f"found {len(nodes)} spectral nodes, expected {ORDER}"
        )

    print("[+] recovered 56 spectral nodes")
    return nodes


# ------------------------------------------------------------
# Recover spectral coefficients
# ------------------------------------------------------------

def recover_coefficients(streams, nodes):
    """
    s[t] = sum_j c[j] * node[j]^t

    First 56 samples give a 56x56 Vandermonde system.
    """

    matrix = [
        [
            pow(node, t, FIELD)
            for node in nodes
        ]
        for t in range(ORDER)
    ]

    coefficients = []

    for lane in range(16):
        values = [
            streams[t][lane]
            for t in range(ORDER)
        ]

        c = gauss_solve(matrix, values)
        coefficients.append(c)

    print("[+] recovered 16 x 56 spectral coefficients")

    return coefficients


# ------------------------------------------------------------
# Predict folded flag stream
# ------------------------------------------------------------

def folded_stream_block(
    block_number,
    nodes,
    coefficients,
):
    """
    Before folding, after 96 oracle blocks:

        state[j] = c[j] * node[j]^96

    fold_for_flag() multiplies each term by:

        node[j]^shift

    where

        shift = 1 + (
            c[j] * (lane+1)
            + (j+3)*(j+7)
        ) mod (FIELD-1)

    Then next_block() returns the sum of those terms.
    """

    result = [0] * 16

    for lane in range(16):
        total = 0

        for j, node in enumerate(nodes):
            c = coefficients[lane][j]

            shift = 1 + (
                (
                    c * (lane + 1)
                    + (j + 3) * (j + 7)
                )
                % (FIELD - 1)
            )

            exponent = block_number + shift

            total += c * pow(node, exponent, FIELD)

        result[lane] = total % FIELD

    return result


# ------------------------------------------------------------
# Inner-word decryption
# ------------------------------------------------------------

def decrypt_inner_word(word, stream_value, q_inv, symbol_perm):
    q_label, row_field, col_field, check_field = split_word(word)

    q = q_inv[q_label]

    high = stream_value >> 8
    mask = (stream_value >> 4) & 15
    low = stream_value & 15

    row_code = SBOX[low]

    base_col = (col_field - 2 * mask) & 15

    if row_field != ((row_code + mask) & 15):
        raise RuntimeError("row field mismatch")

    check = high ^ SBOX[
        (
            row_code
            ^ rotl4(base_col, 1)
            ^ q
            ^ low
        ) & 15
    ]

    if check_field != check:
        raise RuntimeError("check field mismatch")

    symbol = symbol_perm[
        (row_code + base_col) & 15
    ]

    return (
        (q << 4)
        | ((symbol + q) & 15)
    )


def decrypt_flag(
    encrypted_flag,
    streams,
    q_perm,
    symbol_perm,
):
    q_inv = [0] * 16

    for q, label in enumerate(q_perm):
        q_inv[label] = q

    plaintext = bytearray()

    for block_number in range(len(encrypted_flag) // 32):
        ct = encrypted_flag[
            block_number * 32:
            (block_number + 1) * 32
        ]

        ranked = undo_outer_ciphertext(ct)

        stream = streams[block_number]

        rotation = block_rotation(
            stream,
            96 + block_number,
        )

        words = [None] * 16

        for rank, word in enumerate(ranked):
            original_index = (
                rank + rotation
            ) & 15
            words[original_index] = word

        for i in range(16):
            plaintext.append(
                decrypt_inner_word(
                    words[i],
                    stream[i],
                    q_inv,
                    symbol_perm,
                )
            )

    # PKCS#7
    amount = plaintext[-1]

    if not 1 <= amount <= 16:
        raise RuntimeError("bad PKCS#7 padding")

    if plaintext[-amount:] != bytes([amount]) * amount:
        raise RuntimeError("bad PKCS#7 padding")

    return bytes(plaintext[:-amount])


# ------------------------------------------------------------
# Recover symbol permutation
# ------------------------------------------------------------

def recover_symbol_perm(nodes, coefficients):
    """
    We actually only need symbol_perm for final decryption.

    It is deterministic from:
        nodes
        coefficients

    exactly as symbol_permutation_from_model() does.
    """
    import hashlib

    data = bytearray(b"spectral-model")

    for node in nodes:
        data.extend(node.to_bytes(2, "big"))

    for lane in coefficients:
        for value in lane:
            data.extend(value.to_bytes(2, "big"))

    key = hashlib.sha256(data).digest()

    # Same HashStream construction, but only need shuffle(range(16)).
    counter = 0
    buf = bytearray()

    def take(n):
        nonlocal counter

        while len(buf) < n:
            h = hashlib.sha256(
                key
                + b"\x00"
                + b"hexadoku-symbols"
                + counter.to_bytes(8, "big")
            ).digest()

            buf.extend(h)
            counter += 1

        result = bytes(buf[:n])
        del buf[:n]
        return result

    def randbelow(limit):
        ceiling = (1 << 32) - ((1 << 32) % limit)

        while True:
            value = int.from_bytes(take(4), "big")
            if value < ceiling:
                return value % limit

    result = list(range(16))

    for i in range(15, 0, -1):
        j = randbelow(i + 1)
        result[i], result[j] = result[j], result[i]

    return result


# ------------------------------------------------------------
# Network
# ------------------------------------------------------------

def recv_until(sock, marker):
    data = bytearray()

    while marker not in data:
        chunk = sock.recv(4096)

        if not chunk:
            raise EOFError("server closed connection")

        data.extend(chunk)

    return bytes(data)


def main():
    print(f"[+] connecting to {HOST}:{PORT}")

    sock = socket.create_connection((HOST, PORT), timeout=10)
    sock.settimeout(10)

    # Initial menu.
    recv_until(sock, b"> ")

    # q = 0..15 and symbol = (low-q) mod 16 = 0.
    chosen_plaintext = bytes(
        (i << 4) | i
        for i in range(16)
    )

    ciphertexts = []

    print("[+] collecting 96 oracle blocks...")

    for block_number in range(QUERIES):
        sock.sendall(b"1\n")
        recv_until(sock, b"plaintext hex> ")

        sock.sendall(
            chosen_plaintext.hex().encode()
            + b"\n"
        )

        response = recv_until(sock, b"> ")

        match = re.search(
            rb"ciphertext:\s*([0-9a-fA-F]{64})",
            response,
        )

        if not match:
            raise RuntimeError(
                "could not parse ciphertext"
            )

        ct = bytes.fromhex(
            match.group(1).decode()
        )

        ciphertexts.append(ct)

        if (block_number + 1) % 8 == 0:
            print(
                f"    {block_number + 1}/96"
            )

    # Ask for encrypted flag.
    print("[+] requesting encrypted flag...")

    sock.sendall(b"2\n")
    response = recv_until(sock, b"> ")

    match = re.search(
        rb"encrypted flag:\s*([0-9a-fA-F]+)",
        response,
    )

    if not match:
        raise RuntimeError(
            "could not parse encrypted flag"
        )

    encrypted_flag = bytes.fromhex(
        match.group(1).decode()
    )

    sock.close()

    print(
        f"[+] encrypted flag: "
        f"{encrypted_flag.hex()}"
    )

    # Recover stream.
    state = recover_stream(ciphertexts)

    symbol_inv_zero = state["c"]
    q_perm = state["qmap"]
    streams = state["streams"]

    print(
        f"[+] symbol_inv[0] = {symbol_inv_zero}"
    )
    print(
        f"[+] q_perm = {list(q_perm)}"
    )

    # Common spectral recurrence.
    recurrence = recover_recurrence(streams)

    # Spectral nodes.
    nodes = recover_nodes(recurrence)

    # Coefficients.
    coefficients = recover_coefficients(
        streams,
        nodes,
    )

    # Verify the recovered model against every oracle sample.
    print("[+] verifying spectral model...")

    for t in range(96):
        for lane in range(16):
            expected = sum(
                coefficients[lane][j]
                * pow(nodes[j], t, FIELD)
                for j in range(56)
            ) % FIELD

            if expected != streams[t][lane]:
                raise RuntimeError(
                    f"model verification failed "
                    f"at block {t}, lane {lane}"
                )

    print("[+] spectral model verified")

    # After 96 oracle blocks, folding happens.
    # folded0 = folded_stream_block(
    #     96,
    #     nodes,
    #     coefficients,
    # )

    # folded1 = folded_stream_block(
    #     97,
    #     nodes,
    #     coefficients,
    # )

    # Recreate symbol permutation.
    symbol_perm = recover_symbol_perm(
        nodes,
        coefficients,
    )

    # # Flag is expected to be 1 or more 16-byte blocks.
    # # Its folded stream begins at block number 96.
    # flag_streams = [folded0, folded1]

    flag_blocks = len(encrypted_flag) // 32

    flag_streams = [
        folded_stream_block(
            96 + block_number,
            nodes,
            coefficients,
        )
        for block_number in range(flag_blocks)
    ]

    print(f"[+] generating {flag_blocks} folded flag stream blocks")

    plaintext = decrypt_flag(
        encrypted_flag,
        flag_streams,
        q_perm,
        symbol_perm,
    )

    print()
    print("=" * 60)
    print("FLAG:", plaintext.decode())
    print("=" * 60)


if __name__ == "__main__":
    main()