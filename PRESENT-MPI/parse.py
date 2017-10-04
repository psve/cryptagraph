import sys
import struct

with open(sys.argv[1], 'r') as f:
    data = f.read()

elem = [data[i:i+8] for i in range(0, len(data), 8)]
elem = map(lambda x: struct.unpack('<Q', x)[0], elem)

for e in elem:
    print '%016x' % e

print 'total:', len(elem), 'masks'
