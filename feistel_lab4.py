from struct import pack,unpack
from binascii import unhexlify
from time import sleep


def f(RE, k):
    """Function that rotates the bytes k places"""
    lst = RE
    return lst[k:] + lst[:k]


def f1(RE, k):
    """Function that adds itself to each byte"""
    return [b + k for b in RE]


def f2(RE, k):
    """Function that adds itself to 1 byte"""
    i = k % len(RE)
    result = RE[:]
    result[i] = (k + RE[i]) % 256
    return result


def xor_list(LE, RE_f):
    result = []
    for index, c in enumerate(LE):
        result.append(c ^ RE_f[index])
    return result


def execute_round(b_string, keys, round):
    assert(len(b_string) == 8)
    LE = b_string[:4]
    RE = b_string[4:]
    RE_f = f(RE, keys[round])
    return RE + xor_list(LE, RE_f)


def encrypt_bstr(bstr, keys):
    """Takes a byte string and outputs a byte string"""
    last = list(bstr)
    for round in range(len(keys)):
        last = execute_round(last, keys, round)
        print("\r{hex} | {printable} | ROUND {round}".format(
            hex=bstr2hex(last),
            printable=to_printable(last),
            round=round + 1
        ))
        sleep(0.25)
    
    # Swap both sides
    swapped = last[4:] + last[:4]

    return b''.join(map(lambda x: pack("B", x), swapped))


def bstr2hex(s):
    return " ".join("{:02x}".format(c) for c in s)


def str2hex(s):
    return " ".join("{:02x}".format(ord(c)) for c in s)


def hex2bstr(h):
    return unhexlify(h.replace(' ', ''))


def hex2str(h):
    return unhexlify(h.replace(' ', '')).decode('utf-8')


def to_printable(b_str):
    result = ''
    printable_ascii = range(32, 127)
    for b in list(b_str):
        if b in printable_ascii:
            result += chr(b)
        else:
            result += '�'
    return result

# ------------------------------------------------------------------------------------


input_path = "./input.txt"
output_path = "./encrypted.txt"

with open(input_path, "r") as file:
    plaintext = file.read()
    print("Text to encrypt: " + plaintext)

keys = (12, 44, 52, 77, 20, 4, 200, 250, 102, 237, 3, 111, 13, 77, 22, 17)

while len(plaintext) % 8 != 0:
    plaintext += " "

result = ""
for i in range(int(len(plaintext)/8)):
    str = plaintext[8*i:8*(i+1)]
    str_b = str.encode("utf-8")

    print("Hex representation      | Text     | Stage")
    print("------------------------+----------+----------")
    print("{hex} | {plain} | INPUT".format(
        plain=str,
        hex=str2hex(str)
    ))

    cipher_bytes = encrypt_bstr(str_b, keys)
    cipher_hex = bstr2hex(cipher_bytes)
    print("\r{hex} | {printable} | ENCRYPTED\n".format(
        hex=cipher_hex,
        printable=to_printable(cipher_bytes)
    ))

    result += to_printable(cipher_bytes)

    decrypted_bytes = encrypt_bstr(cipher_bytes, keys[::-1])
    decrypted_hex = bstr2hex(decrypted_bytes)
    print("\r{hex} | {printable} | DECRYPTED\n".format(
        hex=decrypted_hex,
        printable=to_printable(decrypted_bytes)
    ))

    result += " -> "
    result += to_printable(decrypted_bytes) + "\n"

with open(output_path, 'w+', encoding="utf-8") as fw:
    fw.write(result)
