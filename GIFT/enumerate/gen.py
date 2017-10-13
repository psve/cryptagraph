
perm = ''
perm += ' 0 17 34 51 48 1 18 35 32 49 2 19 16 33 50 3'
perm += ' 4 21 38 55 52 5 22 39 36 53 6 23 20 37 54 7'
perm += ' 8 25 42 59 56 9 26 43 40 57 10 27 24 41 58 11'
perm += ' 12 29 46 63 60 13 30 47 44 61 14 31 28 45 62 15'

index = map(int, filter(lambda x: x, perm.split(' ')))

assert len(set(index)) == len(index)

for i, o in enumerate(index):
    print '0x%016xL,' % (1 << o)
