import sys

# inverts a byte-wise described 64-bit bit-permuation

size = 64
lbin = bin
def bin(x):
    return ('%%0%ds' % size) % lbin(x)[2:]

with open(sys.argv[1], 'r') as f:
    d = f.read()
    p = eval(d)

inv = {}
for i in range(size):
    b = p[i / 8][1 << (i % 8)]
    inv[b] = 1 << i
    assert bin(b).count('1') == 1

table = []
for off in range(0, size, 8):
    row = []
    for inp in range(0x100):
        s = inp << off
        o = 0
        # decompose
        for k, v in inv.items():
            if k & s:
                o |= v
        assert bin(inp).count('1') == bin(o).count('1')
        row.append(o)
    table.append(row)

for row in table:
    e = map(lambda x: '0x%016x' % x, row)
    s = [e[i: i+8] for i in range(0, 0x100, 8)]
    print ' [', ', '.join(s[0]), ','
    for v in s[1:-1]:
        print '  ', ', '.join(v), ','
    print '  ', ', '.join(s[-1]), '],'


