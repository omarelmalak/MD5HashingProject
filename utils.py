def get_bit(byte: int, bit_num: int) -> int:
    """ Returns bit number <bit_num> from the right within the <byte> byte.

        USED AS A HELPER FOR _BYTE_TO_BITS.

        FROM CSC148 A2 2023 (HUFFMAN TREES).

    >>> get_bit(0b10110101, 9)
    0
    >>> get_bit(0b10110101, 8)
    0
    >>> get_bit(0b10110101, 7)
    1
    >>> get_bit(0b10110101, 2)
    1
    >>> get_bit(0b10110101, 1)
    0
    >>> get_bit(0b10110101, 0)
    1
    """
    return (byte & (1 << bit_num)) >> bit_num


def byte_to_bits(byte: int) -> str:
    """ Returns the representation of <byte> as a string of bits.

        FROM CSC148 A2 2023 (HUFFMAN TREES).

    >>> byte_to_bits(14)
    '00001110'

    >>> bytes = int_to_bytes(int('2bd309f0', 16))
    >>> a = ''.join(byte_to_bits(byte) for byte in bytes)
    >>> a
    '00101011110100110000100111110000'

    >>> bytes = int_to_bytes(int('ABC123EFFF', 16))
    >>> a = ''.join(byte_to_bits(byte) for byte in bytes)
    >>> a
    '000000001010101111000001001000111110111111111111'
    """
    return "".join([str(get_bit(byte, bit_num))
                    for bit_num in range(7, -1, -1)])


def get_bytes(input_string: str) -> bytes:
    """ Returns the inputted string converted to bytes using ASCII reference.

    >>> inp = '5'
    >>> get_bytes(inp)
    b'5'

    >>> inp = '5afdjahf4m2ja'
    >>> get_bytes(inp)
    b'5afdjahf4m2ja'
    """
    return bytes(input_string, 'ascii')


def get_bits_as_string(input: str) -> str:
    """ Returns the bits in string format of the inputted string.

    >>> inp = '0'
    >>> get_bits_as_string(inp)
    '00110000'

    >>> inp = '2'
    >>> get_bits_as_string(inp)
    '00110010'
    """
    input_in_bytes = get_bytes(input)
    bits_lst = [byte_to_bits(byte) for byte in input_in_bytes]
    return ' '.join(bits_lst)


def get_number_of_bits_from_bit_string(bit_string: str) -> int:
    """ Return the number of bits in a bit string.

    >>> bit_str = "11010110 10101101 01010101"
    >>> get_number_of_bits_from_bit_string(bit_str)
    24

    >>> bit_str = "110101101010110101010101"
    >>> get_number_of_bits_from_bit_string(bit_str)
    24
    """
    return len(bit_string) - bit_string.count(' ')


def int_to_bytes(num: int) -> bytes:
    """ Returns the <num> integer converted to a bytes object.

    FROM CSC148 A2 2023 (HUFFMAN TREES).

    >>> list(int_to_bytes(400))
    [1, 144]
    """
    # big-endian representation of num
    return num.to_bytes((num.bit_length() // 8) + 1, "big")