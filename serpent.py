import binascii
import sys
import re


def s(box, input):
    return SBox_bitstring[box % 8][input]


def s_inverse(box, output):
    return s_box_bitstringInverse[box % 8][output]


def s_hat(box, input):
    result = ""
    for i in range(32):
        result = result + s(box, input[4 * i:4 * (i + 1)])
    return result


def s_hat_inverse(box, output):
    result = ""
    for i in range(32):
        result = result + s_inverse(box, output[4 * i:4 * (i + 1)])
    return result


def s_bitslice(box, words):
    result = ["", "", "", ""]
    for i in range(32):  # ideally in parallel
        quad = s(box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def s_bitsliceInverse(box, words):
    result = ["", "", "", ""]
    for i in range(32):  # ideally in parallel
        quad = s_inverse(
            box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def LT(input):
    if len(input) != 128:
        raise ValueError("input to LT is not 128 bit long")

    result = ""
    for i in range(len(LT_table)):
        outputBit = "0"
        for j in LT_table[i]:
            outputBit = xor(outputBit, input[j])
        result = result + outputBit
    return result


def LT_inverse(output):
    if len(output) != 128:
        raise ValueError("input to inverse LT is not 128 bit long")

    result = ""
    for i in range(len(LT_table_inverse)):
        inputBit = "0"
        for j in LT_table_inverse[i]:
            inputBit = xor(inputBit, output[j])
        result = result + inputBit
    return result


def LT_bitslice(X):
    X[0] = rotateLeft(X[0], 13)
    X[2] = rotateLeft(X[2], 3)
    X[1] = xor(X[1], X[0], X[2])
    X[3] = xor(X[3], X[2], shift_left(X[0], 3))
    X[1] = rotateLeft(X[1], 1)
    X[3] = rotateLeft(X[3], 7)
    X[0] = xor(X[0], X[1], X[3])
    X[2] = xor(X[2], X[3], shift_left(X[1], 7))
    X[0] = rotateLeft(X[0], 5)
    X[2] = rotateLeft(X[2], 22)

    return X


def LT_bitsliceInverse(X):
    X[2] = rotate_right(X[2], 22)
    X[0] = rotate_right(X[0], 5)
    X[2] = xor(X[2], X[3], shift_left(X[1], 7))
    X[0] = xor(X[0], X[1], X[3])
    X[3] = rotate_right(X[3], 7)
    X[1] = rotate_right(X[1], 1)
    X[3] = xor(X[3], X[2], shift_left(X[0], 3))
    X[1] = xor(X[1], X[0], X[2])
    X[2] = rotate_right(X[2], 3)
    X[0] = rotate_right(X[0], 13)

    return X


def IP(input):
    return apply_permutation(IP_table, input)


def FP(input):
    return apply_permutation(FP_table, input)


def IP_inverse(output):
    return FP(output)


def FP_inverse(output):
    return IP(output)


def apply_permutation(permutation_table, input):
    if len(input) != len(permutation_table):
        raise ValueError("input size (%d) doesn't match perm table size (%d)" \
                         % (len(input), len(permutation_table)))

    result = ""
    for i in range(len(permutation_table)):
        result = result + input[permutation_table[i]]
    return result

#Ri(X) = L(Si(X ⊕ Ki)) i = 0,..., 30
def R(i, B_hati, K_hat):
    O.show("BHati", B_hati, "(i=%2d) BHati" % i)

    # xored = X ⊕ Ki
    xored = xor(B_hati, K_hat[i])
    O.show("xored", xored, "(i=%2d) xored" % i)

    # xored = Si(i, res), return here plain text after S-box: i = number of box, xored(key) -> (value)
    SHati = s_hat(i, xored)
    O.show("SHati", SHati, "(i=%2d) SHati" % i)

    #if it's not the last round do: linear function
    # Ri(X) = L(SHati) i = 0,..., 30
    if 0 <= i <= r - 2:
        BHatiPlus1 = LT(SHati)
    # Ri(X) = SHati ⊕ K32 i = 31
    elif i == r - 1:
        BHatiPlus1 = xor(SHati, K_hat[r])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, r - 1))
    O.show("BHatiPlus1", BHatiPlus1, "(i=%2d) BHatiPlus1" % i)

    return BHatiPlus1


def R_inverse(i, BHatiPlus1, KHat):
    O.show("BHatiPlus1", BHatiPlus1, "(i=%2d) BHatiPlus1" % i)

    if 0 <= i <= r - 2:
        SHati = LT_inverse(BHatiPlus1)
    elif i == r - 1:
        SHati = xor(BHatiPlus1, KHat[r])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, r - 1))
    O.show("SHati", SHati, "(i=%2d) SHati" % i)

    xored = s_hat_inverse(i, SHati)
    O.show("xored", xored, "(i=%2d) xored" % i)

    BHati = xor(xored, KHat[i])
    O.show("BHati", BHati, "(i=%2d) BHati" % i)

    return BHati


def R_bitslice(i, Bi, K):
    O.show("Bi", Bi, "(i=%2d) Bi" % i)

    # 1. Key mixing
    xored = xor(Bi, K[i])
    O.show("xored", xored, "(i=%2d) xored" % i)

    # 2. S Boxes
    Si = s_bitslice(i, quad_split(xored))
    # Input and output to SBitslice are both lists of 4 32-bit bitstrings
    O.show("Si", Si, "(i=%2d) Si" % i, "tlb")

    # 3. Linear Transformation
    if i == r - 1:
        # In the last round, replaced by an additional key mixing
        BiPlus1 = xor(quad_join(Si), K[r])
    else:
        BiPlus1 = quad_join(LT_bitslice(Si))
    # BIPlus1 is a 128-bit bitstring
    O.show("BiPlus1", BiPlus1, "(i=%2d) BiPlus1" % i)

    return BiPlus1


def R_bitslice_inverse(i, BiPlus1, K):
    O.show("BiPlus1", BiPlus1, "(i=%2d) BiPlus1" % i)

    # 3. Linear Transformation
    if i == r - 1:
        # In the last round, replaced by an additional key mixing
        Si = quad_split(xor(BiPlus1, K[r]))
    else:
        Si = LT_bitsliceInverse(quad_split(BiPlus1))
    # SOutput (same as LTInput) is a list of 4 32-bit bitstrings

    O.show("Si", Si, "(i=%2d) Si" % i, "tlb")

    # 2. S Boxes
    xored = s_bitsliceInverse(i, Si)
    # SInput and SOutput are both lists of 4 32-bit bitstrings

    O.show("xored", xored, "(i=%2d) xored" % i)

    # 1. Key mixing
    Bi = xor(quad_join(xored), K[i])

    O.show("Bi", Bi, "(i=%2d) Bi" % i)

    return Bi


def encrypt(plain_text, user_key):
    O.show("fnTitle", "encrypt", None, "tu")
    O.show("plainText", plain_text, "plainText")
    O.show("userKey", user_key, "userKey")

    #K = 32 Keys , KHat = 32 Keys after IP
    K, KHat = make_subkeys(user_key)

    BHat = IP(plain_text)  # BHat_0 at this stage
    for i in range(r):
        BHat = R(i, BHat, KHat)  # Produce BHat_i+1 from BHat_i
    # BHat is now _32 i.e.
    # BHat is the cipher text, FP is the final permutation
    C = FP(BHat) #FP = IP^-1 Hofhi

    O.show("cipherText", C, "cipherText")

    return C


def encrypt_bitslice(plainText, userKey):
    O.show("fnTitle", "encryptBitslice", None, "tu")
    O.show("plainText", plainText, "plainText")
    O.show("userKey", userKey, "userKey")

    K, KHat = make_subkeys(userKey)

    B = plainText  # B_0 at this stage
    for i in range(r):
        B = R_bitslice(i, B, K)  # Produce B_i+1 from B_i
    # B is now _r

    O.show("cipherText", B, "cipherText")

    return B


def decrypt(cipher_text, user_key):
    O.show("fnTitle", "decrypt", None, "tu")
    O.show("cipherText", cipher_text, "cipherText")
    O.show("userKey", user_key, "userKey")

    K, KHat = make_subkeys(user_key)

    BHat = FP_inverse(cipher_text)  # BHat_r at this stage
    #Takes subkeys from the end (31) to the start (0)
    for i in range(r - 1, -1, -1):  # from r-1 down to 0 included
        BHat = R_inverse(i, BHat, KHat)  # Produce BHat_i from BHat_i+1
    # BHat is now _0
    plainText = IP_inverse(BHat)

    O.show("plainText", plainText, "plainText")
    return plainText


def decrypt_bitslice(cipher_text, user_key):
    O.show("fnTitle", "decryptBitslice", None, "tu")
    O.show("cipherText", cipher_text, "cipherText")
    O.show("userKey", user_key, "userKey")

    K, KHat = make_subkeys(user_key)

    B = cipher_text  # B_r at this stage
    for i in range(r - 1, -1, -1):  # from r-1 down to 0 included
        B = R_bitslice_inverse(i, B, K)  # Produce B_i from B_i+1
    # B is now _0

    O.show("plainText", B, "plainText")
    return B


def make_subkeys(user_key):
    """
Create a 32 sub keys outof the shaerd key.
    :param user_key:
    :return:
    """
    #Take 256bit original key and devided to 8 words
    w = {}
    for i in range(-8, 0):
        w[i] = user_key[(i + 8) * 32:(i + 9) * 32]
        O.show("wi", w[i], "(i=%2d) wi" % i)

    # We expand these to a prekey w0 ... w131 with the affine recurrence
    # wi := (wi−8 ⊕ wi−5 ⊕ wi−3 ⊕ wi−1 ⊕ φ ⊕ i) <<< 11
    #with the addition of the round index is chosen to ensure an even distribution of key bits throughout the rounds,
    # and to eliminate weak keys and related keys
    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i - 8], w[i - 5], w[i - 3], w[i - 1],
                bit_string(phi, 32), bit_string(i, 32)),
            11)
        O.show("wi", w[i], "(i=%2d) wi" % i)

    # S-BOX
    # {k0, k1, k2, k3} := S3(w0, w1, w2, w3)
    # {k4, k5, k6, k7} := S2(w4, w5, w6, w7)
    # {k8, k9, k10, k11} := S1(w8, w9, w10, w11)
    # {k12, k13, k14, k15} := S0(w12, w13, w14, w15)
    # {k16, k17, k18, k19} := S7(w16, w17, w18, w19)
    # ...
    # {k124, k125, k126, k127} := S4(w124, w125, w126, w127)
    # {k128, k129, k130, k131} := S3(w128, w129, w130, w131)
    k = {}
    for i in range(r + 1):
        whichS = (r + 3 - i) % r
        k[0 + 4 * i] = ""
        k[1 + 4 * i] = ""
        k[2 + 4 * i] = ""
        k[3 + 4 * i] = ""
        for j in range(32):  # for every bit in the k and w words
            input = w[0 + 4 * i][j] + w[1 + 4 * i][j] + w[2 + 4 * i][j] + w[3 + 4 * i][j]
            output = s(whichS, input)
            for l in range(4):
                k[l + 4 * i] = k[l + 4 * i] + output[l]

    #Ki := {k4i, k4i+1, k4i+2, k4i+3} here we create 32 subkeys
    K = []
    for i in range(33):
        K.append(k[4 * i] + k[4 * i + 1] + k[4 * i + 2] + k[4 * i + 3])

    #Initial Permutation
    KHat = []
    for i in range(33):
        KHat.append(IP(K[i]))

        O.show("Ki", K[i], "(i=%2d) Ki" % i)
        O.show("KHati", KHat[i], "(i=%2d) KHati" % i)

    return K, KHat


def make_long_key(k):
    l = len(k)
    if l % 32 != 0 or l < 64 or l > 256:
        raise ValueError("Invalid key length (%d bits)" % l)

    if l == 256:
        return k
    else:
        return k + "1" + "0" * (256 - l - 1)


def bit_string(n, minlen=1):
    if minlen < 1:
        raise ValueError("a bitstring must have at least 1 char")
    if n < 0:
        raise ValueError("bitstring representation undefined for neg numbers")

    result = ""
    while n > 0:
        if n & 1:
            result = result + "1"
        else:
            result = result + "0"
        n = n >> 1
    if len(result) < minlen:
        result = result + "0" * (minlen - len(result))
    return result


def binary_xor(n1, n2):
    if len(n1) != len(n2):
        raise ValueError("can't xor bitstrings of different " + \
                         "lengths (%d and %d)" % (len(n1), len(n2)))

    result = ""
    for i in range(len(n1)):
        if n1[i] == n2[i]:
            result = result + "0"
        else:
            result = result + "1"
    return result


def xor(*args):
    if args == []:
        raise ValueError("at least one argument needed")

    result = args[0]
    for arg in args[1:]:
        result = binary_xor(result, arg)
    return result


def rotateLeft(input, places):
    p = places % len(input)
    return input[-p:] + input[:-p]


def rotate_right(input, places):
    return rotateLeft(input, -places)


def shift_left(input, p):
    if abs(p) >= len(input):
        # Everything gets shifted out anyway
        return "0" * len(input)
    if p < 0:
        # Shift right instead
        return input[-p:] + "0" * len(input[:-p])
    elif p == 0:
        return input
    else:  # p > 0, normal case
        return "0" * len(input[-p:]) + input[:-p]


def shift_right(input, p):
    return shift_left(input, -p)


def key_length_in_bits_of(k):
    return len(k) * 4


bin2hex = {
    "0000": "0", "1000": "1", "0100": "2", "1100": "3",
    "0010": "4", "1010": "5", "0110": "6", "1110": "7",
    "0001": "8", "1001": "9", "0101": "a", "1101": "b",
    "0011": "c", "1011": "d", "0111": "e", "1111": "f",
}

hex2bin = {}
for (bin, hex) in bin2hex.items():
    hex2bin[hex] = bin


def bitstring_2_hex_string(b):
    result = ""
    l = len(b)
    if l % 4:
        b = b + "0" * (4 - (l % 4))
    for i in range(0, len(b), 4):
        result = result + bin2hex[b[i:i + 4]]
    return reverse_string(result)


def hexstring_2_bit_string(h):
    result = ""
    for c in reverse_string(h):
        result = result + hex2bin[c]
    return result


def reverse_string(s):
    l = list(s)
    l.reverse()
    return "".join(l)


def quad_split(b128):
    if len(b128) != 128:
        raise ValueError("must be 128 bits long, not " + len(b128))

    result = []
    for i in range(4):
        result.append(b128[(i * 32):(i + 1) * 32])
    return result


def quad_join(l4x32):
    if len(l4x32) != 4:
        raise ValueError("need a list of 4 bitstrings, not " + len(l4x32))

    return l4x32[0] + l4x32[1] + l4x32[2] + l4x32[3]


class Observer:
    typesOfVariable = {
        "tu": "unknown", "tb": "bitstring", "tlb": "list of bitstrings", }

    def __init__(self, tags=[]):
        self.tags = {}
        for tag in tags:
            self.tags[tag] = 1

    def add_tag(self, *tags):
        for t in tags:
            self.tags[t] = 1

    def remove_tag(self, *tags):
        for t in tags:
            if t in self.tags.keys():
                del self.tags[t]

    def show(self, tag, variable, label=None, type="tb"):

        if label == None:
            label = tag
        if "ALL" in self.tags.keys() or tag in self.tags.keys():
            if type == "tu":
                output = repr(variable)
            elif type == "tb":
                output = bitstring_2_hex_string(variable)
            elif type == "tlb":
                output = ""
                for item in variable:
                    output = output + " %s" % bitstring_2_hex_string(item)
                output = "[" + output[1:] + "]"
            else:
                raise ValueError("unknown type: %s. Valid ones are %s" % (
                    type, self.typesOfVariable.keys()))

            print
            label,
            if output:
                print
                "=", output
            else:
                print


O = Observer(["plainText", "userKey", "cipherText"])
phi = 0x9e3779b9
r = 32

# Data tables
# (14, or 0xe).
SBox_decimal_table = [
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],  # S0
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],  # S1
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],  # S2
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],  # S3
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],  # S4
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],  # S5
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],  # S6
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],  # S7
]

SBox_bitstring = []
s_box_bitstringInverse = []
for line in SBox_decimal_table:
    dict = {}
    inverseDict = {}
    for i in range(len(line)):
        index = bit_string(i, 4)
        value = bit_string(line[i], 4)
        dict[index] = value
        inverseDict[value] = index
    SBox_bitstring.append(dict)
    s_box_bitstringInverse.append(inverseDict)

IP_table = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
]
FP_table = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
]

LT_table = [
    [16, 52, 56, 70, 83, 94, 105],
    [72, 114, 125],
    [2, 9, 15, 30, 76, 84, 126],
    [36, 90, 103],
    [20, 56, 60, 74, 87, 98, 109],
    [1, 76, 118],
    [2, 6, 13, 19, 34, 80, 88],
    [40, 94, 107],
    [24, 60, 64, 78, 91, 102, 113],
    [5, 80, 122],
    [6, 10, 17, 23, 38, 84, 92],
    [44, 98, 111],
    [28, 64, 68, 82, 95, 106, 117],
    [9, 84, 126],
    [10, 14, 21, 27, 42, 88, 96],
    [48, 102, 115],
    [32, 68, 72, 86, 99, 110, 121],
    [2, 13, 88],
    [14, 18, 25, 31, 46, 92, 100],
    [52, 106, 119],
    [36, 72, 76, 90, 103, 114, 125],
    [6, 17, 92],
    [18, 22, 29, 35, 50, 96, 104],
    [56, 110, 123],
    [1, 40, 76, 80, 94, 107, 118],
    [10, 21, 96],
    [22, 26, 33, 39, 54, 100, 108],
    [60, 114, 127],
    [5, 44, 80, 84, 98, 111, 122],
    [14, 25, 100],
    [26, 30, 37, 43, 58, 104, 112],
    [3, 118],
    [9, 48, 84, 88, 102, 115, 126],
    [18, 29, 104],
    [30, 34, 41, 47, 62, 108, 116],
    [7, 122],
    [2, 13, 52, 88, 92, 106, 119],
    [22, 33, 108],
    [34, 38, 45, 51, 66, 112, 120],
    [11, 126],
    [6, 17, 56, 92, 96, 110, 123],
    [26, 37, 112],
    [38, 42, 49, 55, 70, 116, 124],
    [2, 15, 76],
    [10, 21, 60, 96, 100, 114, 127],
    [30, 41, 116],
    [0, 42, 46, 53, 59, 74, 120],
    [6, 19, 80],
    [3, 14, 25, 100, 104, 118],
    [34, 45, 120],
    [4, 46, 50, 57, 63, 78, 124],
    [10, 23, 84],
    [7, 18, 29, 104, 108, 122],
    [38, 49, 124],
    [0, 8, 50, 54, 61, 67, 82],
    [14, 27, 88],
    [11, 22, 33, 108, 112, 126],
    [0, 42, 53],
    [4, 12, 54, 58, 65, 71, 86],
    [18, 31, 92],
    [2, 15, 26, 37, 76, 112, 116],
    [4, 46, 57],
    [8, 16, 58, 62, 69, 75, 90],
    [22, 35, 96],
    [6, 19, 30, 41, 80, 116, 120],
    [8, 50, 61],
    [12, 20, 62, 66, 73, 79, 94],
    [26, 39, 100],
    [10, 23, 34, 45, 84, 120, 124],
    [12, 54, 65],
    [16, 24, 66, 70, 77, 83, 98],
    [30, 43, 104],
    [0, 14, 27, 38, 49, 88, 124],
    [16, 58, 69],
    [20, 28, 70, 74, 81, 87, 102],
    [34, 47, 108],
    [0, 4, 18, 31, 42, 53, 92],
    [20, 62, 73],
    [24, 32, 74, 78, 85, 91, 106],
    [38, 51, 112],
    [4, 8, 22, 35, 46, 57, 96],
    [24, 66, 77],
    [28, 36, 78, 82, 89, 95, 110],
    [42, 55, 116],
    [8, 12, 26, 39, 50, 61, 100],
    [28, 70, 81],
    [32, 40, 82, 86, 93, 99, 114],
    [46, 59, 120],
    [12, 16, 30, 43, 54, 65, 104],
    [32, 74, 85],
    [36, 90, 103, 118],
    [50, 63, 124],
    [16, 20, 34, 47, 58, 69, 108],
    [36, 78, 89],
    [40, 94, 107, 122],
    [0, 54, 67],
    [20, 24, 38, 51, 62, 73, 112],
    [40, 82, 93],
    [44, 98, 111, 126],
    [4, 58, 71],
    [24, 28, 42, 55, 66, 77, 116],
    [44, 86, 97],
    [2, 48, 102, 115],
    [8, 62, 75],
    [28, 32, 46, 59, 70, 81, 120],
    [48, 90, 101],
    [6, 52, 106, 119],
    [12, 66, 79],
    [32, 36, 50, 63, 74, 85, 124],
    [52, 94, 105],
    [10, 56, 110, 123],
    [16, 70, 83],
    [0, 36, 40, 54, 67, 78, 89],
    [56, 98, 109],
    [14, 60, 114, 127],
    [20, 74, 87],
    [4, 40, 44, 58, 71, 82, 93],
    [60, 102, 113],
    [3, 18, 72, 114, 118, 125],
    [24, 78, 91],
    [8, 44, 48, 62, 75, 86, 97],
    [64, 106, 117],
    [1, 7, 22, 76, 118, 122],
    [28, 82, 95],
    [12, 48, 52, 66, 79, 90, 101],
    [68, 110, 121],
    [5, 11, 26, 80, 122, 126],
    [32, 86, 99],
]

LT_table_inverse = [
    [53, 55, 72],
    [1, 5, 20, 90],
    [15, 102],
    [3, 31, 90],
    [57, 59, 76],
    [5, 9, 24, 94],
    [19, 106],
    [7, 35, 94],
    [61, 63, 80],
    [9, 13, 28, 98],
    [23, 110],
    [11, 39, 98],
    [65, 67, 84],
    [13, 17, 32, 102],
    [27, 114],
    [1, 3, 15, 20, 43, 102],
    [69, 71, 88],
    [17, 21, 36, 106],
    [1, 31, 118],
    [5, 7, 19, 24, 47, 106],
    [73, 75, 92],
    [21, 25, 40, 110],
    [5, 35, 122],
    [9, 11, 23, 28, 51, 110],
    [77, 79, 96],
    [25, 29, 44, 114],
    [9, 39, 126],
    [13, 15, 27, 32, 55, 114],
    [81, 83, 100],
    [1, 29, 33, 48, 118],
    [2, 13, 43],
    [1, 17, 19, 31, 36, 59, 118],
    [85, 87, 104],
    [5, 33, 37, 52, 122],
    [6, 17, 47],
    [5, 21, 23, 35, 40, 63, 122],
    [89, 91, 108],
    [9, 37, 41, 56, 126],
    [10, 21, 51],
    [9, 25, 27, 39, 44, 67, 126],
    [93, 95, 112],
    [2, 13, 41, 45, 60],
    [14, 25, 55],
    [2, 13, 29, 31, 43, 48, 71],
    [97, 99, 116],
    [6, 17, 45, 49, 64],
    [18, 29, 59],
    [6, 17, 33, 35, 47, 52, 75],
    [101, 103, 120],
    [10, 21, 49, 53, 68],
    [22, 33, 63],
    [10, 21, 37, 39, 51, 56, 79],
    [105, 107, 124],
    [14, 25, 53, 57, 72],
    [26, 37, 67],
    [14, 25, 41, 43, 55, 60, 83],
    [0, 109, 111],
    [18, 29, 57, 61, 76],
    [30, 41, 71],
    [18, 29, 45, 47, 59, 64, 87],
    [4, 113, 115],
    [22, 33, 61, 65, 80],
    [34, 45, 75],
    [22, 33, 49, 51, 63, 68, 91],
    [8, 117, 119],
    [26, 37, 65, 69, 84],
    [38, 49, 79],
    [26, 37, 53, 55, 67, 72, 95],
    [12, 121, 123],
    [30, 41, 69, 73, 88],
    [42, 53, 83],
    [30, 41, 57, 59, 71, 76, 99],
    [16, 125, 127],
    [34, 45, 73, 77, 92],
    [46, 57, 87],
    [34, 45, 61, 63, 75, 80, 103],
    [1, 3, 20],
    [38, 49, 77, 81, 96],
    [50, 61, 91],
    [38, 49, 65, 67, 79, 84, 107],
    [5, 7, 24],
    [42, 53, 81, 85, 100],
    [54, 65, 95],
    [42, 53, 69, 71, 83, 88, 111],
    [9, 11, 28],
    [46, 57, 85, 89, 104],
    [58, 69, 99],
    [46, 57, 73, 75, 87, 92, 115],
    [13, 15, 32],
    [50, 61, 89, 93, 108],
    [62, 73, 103],
    [50, 61, 77, 79, 91, 96, 119],
    [17, 19, 36],
    [54, 65, 93, 97, 112],
    [66, 77, 107],
    [54, 65, 81, 83, 95, 100, 123],
    [21, 23, 40],
    [58, 69, 97, 101, 116],
    [70, 81, 111],
    [58, 69, 85, 87, 99, 104, 127],
    [25, 27, 44],
    [62, 73, 101, 105, 120],
    [74, 85, 115],
    [3, 62, 73, 89, 91, 103, 108],
    [29, 31, 48],
    [66, 77, 105, 109, 124],
    [78, 89, 119],
    [7, 66, 77, 93, 95, 107, 112],
    [33, 35, 52],
    [0, 70, 81, 109, 113],
    [82, 93, 123],
    [11, 70, 81, 97, 99, 111, 116],
    [37, 39, 56],
    [4, 74, 85, 113, 117],
    [86, 97, 127],
    [15, 74, 85, 101, 103, 115, 120],
    [41, 43, 60],
    [8, 78, 89, 117, 121],
    [3, 90],
    [19, 78, 89, 105, 107, 119, 124],
    [45, 47, 64],
    [12, 82, 93, 121, 125],
    [7, 94],
    [0, 23, 82, 93, 109, 111, 123],
    [49, 51, 68],
    [1, 16, 86, 97, 125],
    [11, 98],
    [4, 27, 86, 97, 113, 115, 127],
]


def help_exit(message=None):
    if message:
        print("ERROR:", message)
    sys.exit()


def hex_convert_to_bitstring(input, numBits):
    input = input.lower()

    if bool(re.match("^[0-9a-f]+$", input)):
        bitstring = hexstring_2_bit_string(input)
    else:
        raise ValueError("%s is not a valid hexstring" % input)

    # assert: bitstring now contains the bitstring version of the input

    if len(bitstring) > numBits:
        # Last chance: maybe it's got some useless 0s...
        if re.match("^0+$", bitstring[numBits:]):
            bitstring = bitstring[:numBits]
        else:
            raise ValueError("input too large to fit in %d bits" % numBits)
    else:
        bitstring = bitstring + "0" * (numBits - len(bitstring))

    return bitstring


def convert_to_bitstring(text_string, numBits):
    """
converting from text to binary string
    :param text_string:the block we would like to encrypt
    :param numBits: the size of block
    :return:
    """
    bitstring = ''

    for ch in text_string:
        temp = f"{ord(ch):b}"

        if len(temp) < 8:
            temp = "0" * (8 - len(temp)) + temp

        bitstring = bitstring + temp

    if len(bitstring) > numBits:
        if re.match("^0+$", bitstring[numBits:]):
            bitstring = bitstring[:numBits]
        else:
            raise ValueError("input too large to fit in %d bits" % numBits)
    else:
        bitstring = bitstring + "0" * (numBits - len(bitstring))

    return bitstring


def bit_string_to_string(text_int_format):
    n = int(text_int_format, 2)
    if n == 0: return ""

    res = binascii.unhexlify('%x' % n)
    res = res.decode('ascii')
    res = res.rstrip('\x00')

    return res

#We can send to algoritum only string of 12 chars (128 bits block)
#So we divide the the big text we recive from the GUI:
#number of chars/16 = number of block we need
#We concal the result, and when get the big cipher text.
def encrypt_text(text, key_128):
    # init
    cipherText = ''

    user_key = get_user_key(key_128)

    # genrate plainText
    num_of_blocks = calc_number_of_blocks(text, 16)
    for block_num in range(0, num_of_blocks): #iterating over each block and encrypt
        start_index = block_num * 16
        text_block = text[start_index:start_index + 16]

        plainText = convert_to_bitstring(text_block, 128)
        cipherText = cipherText + encrypt(plainText, user_key)

    return cipherText


def calc_number_of_blocks(text, n):
    print("calculate number of blocks...")
    num_of_blocks = int(len(text) / n)#dividing the input plain-text to blocks, each block in size 128-bits

    if (len(text) % n) != 0:
        num_of_blocks = num_of_blocks + 1

    print("[Validation] "+str(len(text)) + "/" + str(n) + " = " + str(len(text) / n) + " => needs '" + str(num_of_blocks) + "' blocks")
    return num_of_blocks


def decrypt_text(cipher_text, key_128):
    # init
    text = ''
    user_key = get_user_key(key_128)

    # genrate plainText
    num_of_blocks = calc_number_of_blocks(cipher_text, 128)
    for block_num in range(0, num_of_blocks):
        start_index = block_num * 128
        text_block = cipher_text[start_index:start_index + 128]

        row_plain_text = decrypt(text_block, user_key)
        text = text + bit_string_to_string(row_plain_text)

    return text


def get_user_key(key_128):
    # genrate userKey
    bits_in_key = key_length_in_bits_of(key_128)#the lenght of the key, in our case 256-bit
    raw_key = hex_convert_to_bitstring(key_128, bits_in_key)
    user_key = make_long_key(raw_key)

    return user_key


def get_formatted_cipher_text(cipher_text):
    text = ''
    # genrate plainText
    num_of_blocks = int("{:.0f}".format(len(cipher_text) / 16))
    for block_num in range(0, num_of_blocks):
        start_index = block_num * 16
        text_block = cipher_text[start_index:start_index + 16]

        n = int(text_block, 2)
        res = binascii.unhexlify('%x' % n)
        res = res.strip()
        res = res.decode('utf-8', 'ignore')

        text = text + res

    return text


def main():
    text = "dam"

    key_128 = "AF1AB8CDC2128A97AF1AB8CDCA128a93AF1AB8CDC2128A97AF1AB8CDCA128a9a"

    cipher_text = encrypt_text(text, key_128)
    print(cipher_text)
    res = decrypt_text(cipher_text, key_128)
    print(res)


if __name__ == "__main__":
    main()