#!/usr/bin/env python3
"""Demonstracao passo a passo do off-by-null e de uma correcao segura.

Uso: python3 solver/off_by_null_fix.py

O exemplo simula os bytes em buffers Python; nao inicia o binario do desafio
nem escreve em metadados reais da heap.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class CopyResult:
    requested_size: int
    input_length: int
    terminator_offset: int
    overflow_bytes: int
    next_chunk_size: int


class BeforeFix:
    """Modela read(size) seguido de strcpy em um destino de size bytes."""

    @staticmethod
    def copy(requested_size, data, next_chunk_size):
        text = data.split(b"\0", 1)[0]
        terminator_offset = len(text)
        overflow_bytes = max(0, terminator_offset + 1 - requested_size)
        size_bytes = bytearray(next_chunk_size.to_bytes(8, "little"))
        if overflow_bytes:
            size_bytes[0] = 0
        resulting_size = int.from_bytes(size_bytes, "little")
        return CopyResult(
            requested_size=requested_size,
            input_length=len(data),
            terminator_offset=terminator_offset,
            overflow_bytes=overflow_bytes,
            next_chunk_size=resulting_size,
        )


class AfterFix:
    """Modela um destino de size + 1 bytes para o terminador NUL."""

    @staticmethod
    def copy(requested_size, data, next_chunk_size):
        if requested_size < 0:
            raise ValueError("o tamanho solicitado nao pode ser negativo")
        if len(data) > requested_size:
            raise ValueError("entrada maior que o tamanho solicitado")

        # A capacidade extra garante que o NUL escrito por strcpy caiba.
        storage = bytearray(requested_size + 1)
        storage[:len(data)] = data
        storage[len(data)] = 0
        return storage, CopyResult(
            requested_size=requested_size,
            input_length=len(data),
            terminator_offset=len(data),
            overflow_bytes=0,
            next_chunk_size=next_chunk_size,
        )


def main():
    requested_size = 0x108
    neighbor_size = 0x111
    boundary_input = b"A" * requested_size

    print("=== Antes da correcao: read(size) + strcpy(dest, buf) ===")
    print(f"1. malloc({requested_size:#x}) reserva o destino.")
    print(
        f"2. O chunk vizinho tem size={neighbor_size:#x}; "
        f"seu byte menos significativo e {neighbor_size & 0xff:#04x}."
    )
    print(
        f"3. read recebe {len(boundary_input):#x} bytes sem NUL; "
        "a entrada ocupa exatamente o tamanho solicitado."
    )
    print(
        f"4. strcpy copia os bytes e acrescenta NUL no offset "
        f"{requested_size:#x}, fora do destino."
    )
    before = BeforeFix.copy(requested_size, boundary_input, neighbor_size)
    assert before.overflow_bytes == 1
    assert before.next_chunk_size == 0x100
    print(
        f"5. O NUL troca o byte {neighbor_size & 0xff:#04x} por 0x00: "
        f"size {neighbor_size:#x} -> {before.next_chunk_size:#x} "
        "(PREV_INUSE fica limpo)."
    )

    print("\n=== Depois da correcao: destino com size + 1 bytes ===")
    print(
        f"1. Reservar {requested_size + 1:#x} bytes para {requested_size:#x} "
        "bytes de entrada e o terminador."
    )
    storage, after = AfterFix.copy(
        requested_size, boundary_input, neighbor_size
    )
    assert len(storage) == requested_size + 1
    assert storage[requested_size] == 0
    assert after.overflow_bytes == 0
    assert after.next_chunk_size == neighbor_size
    print(
        f"2. Copiar {after.input_length:#x} bytes; o NUL fica no offset "
        f"{after.terminator_offset:#x}, dentro do destino."
    )
    print(
        f"3. Escrita fora do destino: {after.overflow_bytes}; "
        f"size vizinho permanece {after.next_chunk_size:#x}."
    )


if __name__ == "__main__":
    main()
