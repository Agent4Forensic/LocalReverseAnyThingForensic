# vm_stub.py - toy byte-code loader, benchmark sample, never executed
import base64, gzip

TABLE = bytes.fromhex("5ac3e1094f7d22b8d6013e94a7cc60f5")   # 16 bytes, key bytes are TABLE[i & 15]

# opcodes: 01 UNHEX | 02 n i1..in XORK (key = TABLE[i & 15] for each index, repeated) | 03 B64 decode
#          04 GUNZIP | 0A NOP | FF HALT
def run(prog, buf):
    pc = 0
    while True:
        op = prog[pc]
        if op == 0x01:
            buf = bytes.fromhex(buf.decode()); pc += 1
        elif op == 0x02:
            n = prog[pc + 1]
            key = bytes(TABLE[i & 15] for i in prog[pc + 2:pc + 2 + n])
            buf = bytes(b ^ key[j % n] for j, b in enumerate(buf)); pc += 2 + n
        elif op == 0x03:
            buf = base64.b64decode(buf); pc += 1
        elif op == 0x04:
            buf = gzip.decompress(buf); pc += 1
        elif op == 0x0A:
            pc += 1
        elif op == 0xFF:
            return buf

PROG = bytes.fromhex("0a010204031b0c25030a020307122f04ff")
PROG_DEBUG = bytes.fromhex("01ff")   # only used when DEBUG is set, it is not
DEBUG = False
DATA_DEBUG = b"464c41477b64656275675f706174685f69735f615f6465636f797d"
DATA = "79a6d5447cdbef4c7cdbef4e5ba3ec1731dfce496de5914530f6e31965e5ce4830e3f31b31e7d04465acd34565edc04b30fdde104ad8f3447de4c6355dceee394cd99f5647f7914530d7d24547f7914b6dd7cf4a63a2dd384cf3f6526ad9901f7cc1d11965f5ca4565dfc01a31a4de446dd9d04431c0f6566dd9d6566dd7ce485ef1f74c5af9f23948a3c94c7cdbe240"
# print(run(PROG, DATA))  # disabled in the sample
