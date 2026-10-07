
import struct, sys
d = open(sys.argv[1], 'rb').read()
print('PNG signature OK:', d[:8] == b'\x89PNG\r\n\x1a\n')
i = 8
found_iend = False
while i + 8 <= len(d):
    length, ctype = struct.unpack('>I4s', d[i:i+8])
    print(i, ctype.decode('latin-1'), length)
    if ctype in (b'tEXt', b'iTXt', b'zTXt'):
        print('   ', d[i+8:i+8+min(length, 200)])
    i += 12 + length
    if ctype == b'IEND':
        found_iend = True
        break
print('File size:', len(d))
print('IEND found:', found_iend, ' bytes after IEND:', len(d) - i if found_iend else 'n/a')
