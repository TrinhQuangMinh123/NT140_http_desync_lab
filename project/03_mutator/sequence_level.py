#!/usr/bin/env python3
"""
sequence_level.py - Sequence-Level HTTP Mutator
-------------------------------------------------
Replicates HDHunter's SequenceSpliceMutator and SequenceRemoveMutator.
Operates on a *sequence* (list) of HTTP messages, adding or removing
messages to abuse HTTP pipelining.

HDHunter Reference:
    hdhunter/src/mutators/sequence.rs
      - SequenceSpliceMutator: insert a random corpus request into the pipeline
      - SequenceRemoveMutator: drop a request from the pipeline
"""

import random
from typing import List

# Maximum pipeline depth HDHunter allows (mirrors the Rust impl's limit of 3)
MAX_PIPELINE_DEPTH = 3


def sequence_splice(sequence: List[bytes], corpus: List[bytes]) -> List[bytes]:
    """
    Sequence-level Splice Mutator
    ------------------------------
    Inserts a randomly chosen request from the seed corpus into a random
    position inside the current pipeline sequence.

    Mirrors: SequenceSpliceMutator in HDHunter (sequence.rs)

    Args:
        sequence: Current list of raw HTTP messages (bytes).
        corpus:   Full seed corpus to sample from.

    Returns:
        Mutated sequence with one extra request inserted.
        Returns the original sequence unchanged if max depth is already reached.
    """
    if len(sequence) >= MAX_PIPELINE_DEPTH:
        return sequence  # Skipped — depth cap reached

    donor = random.choice(corpus)
    insert_pos = random.randint(0, len(sequence))
    mutated = sequence[:insert_pos] + [donor] + sequence[insert_pos:]
    return mutated


def sequence_remove(sequence: List[bytes]) -> List[bytes]:
    """
    Sequence-level Remove Mutator
    ------------------------------
    Drops a random request from the pipeline to shrink the sequence.

    Mirrors: SequenceRemoveMutator in HDHunter (sequence.rs)

    Args:
        sequence: Current list of raw HTTP messages (bytes).

    Returns:
        Mutated sequence with one request removed.
        Returns the original sequence unchanged if only 1 request remains.
    """
    if len(sequence) < 2:
        return sequence  # Skipped — would result in empty pipeline

    remove_pos = random.randint(0, len(sequence) - 1)
    return sequence[:remove_pos] + sequence[remove_pos + 1:]


def pipeline_encode(sequence: List[bytes]) -> bytes:
    """
    Concatenates a sequence of HTTP messages into one raw TCP payload,
    simulating HTTP/1.1 pipelining (multiple requests in a single connection).
    """
    return b"".join(sequence)


# -------------- Unit Tests --------------
if __name__ == "__main__":
    seed_a = b"GET / HTTP/1.1\r\nHost: target.com\r\nConnection: keep-alive\r\n\r\n"
    seed_b = b"POST /post HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\n\r\nDATA"
    seed_c = b"OPTIONS * HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n"
    corpus  = [seed_a, seed_b, seed_c]

    print("=== Sequence-Level Mutator Demo ===\n")

    pipeline = [seed_a]
    print(f"[original] pipeline depth = {len(pipeline)}")

    spliced = sequence_splice(pipeline, corpus)
    print(f"[splice]   pipeline depth = {len(spliced)}")

    removed = sequence_remove(spliced)
    print(f"[remove]   pipeline depth = {len(removed)}")

    raw_payload = pipeline_encode(spliced)
    print(f"\n[pipelined payload ({len(raw_payload)} bytes)]")
    print(raw_payload.decode('latin-1', errors='replace'))
