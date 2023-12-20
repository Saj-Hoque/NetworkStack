def to_32bit(char):
    return char[2:].zfill(32)

def to_text(binary):
    return chr(binary)
    
def encode_to_binary(text):
    return ''.join(map(to_32bit, map(bin, bytearray(text, 'utf8'))))

def decode_to_text(binary):
    return ''.join(map(to_text, [int(binary[i:i+32], 2) for i in range(0, len(binary), 32)]))

a = "GET / HTTP/1.1"
b = encode_to_binary(a)
print(b)
c = decode_to_text(b)
print(c)
