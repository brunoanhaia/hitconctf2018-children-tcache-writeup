#!/usr/bin/env bash
# Executa o desafio com a glibc 2.27 do handout (sem usar o loader do sistema).
set -euo pipefail
cd "$(dirname "$0")/challenge"
exec ./ld-2.27.so --library-path . ./children_tcache
