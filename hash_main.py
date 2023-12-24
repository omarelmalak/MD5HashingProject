import utils
from blockcollection import BlockCollection
"""
PROJECT GUIDE REFERENCE:
https://www.comparitech.com/blog/information-security/md5-algorithm-with-examples/
"""

def hash(input_string: str) -> str:
    """
    Takes in input string (attempted password) and provides a MD5 algorithm-based hash result to add to a hash table
    of passwords for an account login system.

    ARTICLE EXAMPLE
    >>> res = hash('They are deterministic')
    >>> res
    >>> len(res)

    # SINGLE ELEMENT EXAMPLE (LOWERCASE)
    >>> res = hash('a')
    >>> res
    >>> len(res)

    # SINGLE ELEMENT EXAMPLE (UPPERCASE)
    >>> res = hash('A')
    >>> res
    >>> len(res)

    OVER 64-bit LENGTH (9,223,372,036,854,775,808 CHARACTERS)
    >>> a = 'a' * 1000
    >>> res = hash(a)
    >>> res
    >>> len(res)

    EXACTLY 1560 (520 * 3) BITS (195 CHARACTERS)
    >>> res = hash('mgmbcihkbcsbswccfkfqpkrxfuxbvnjuwnteqnkedqcbastulcajartugjvahbwwbeqbuixfxbhwevohbyqipnzgvxqhyzqrkdriucnqbcvjcotjbhwxnznodrvkmpdtwxdhbkbdkwuvnfwrbfccfchpachovajyvdoauutsbeibxbnlwhpripoaslqjeobotbo')
    >>> res
    >>> len(res)

    EXACTLY 512 BITS (64 CHARACTERS)
    >>> res = hash('aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfigjaleodif')
    >>> res
    >>> len(res)

    EXACTLY 0 BITS (0 CHARACTERS)
    >>> res = hash('')
    >>> res
    >>> len(res)

    EXACTLY 8 BITS (1 CHARACTER)
    >>> res = hash('h')
    >>> res
    >>> len(res)

    EXACTLY 448 BITS (56 CHARACTERS)
    >>> res = hash('aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfig')
    >>> res
    >>> len(res)

    EXACTLY 456 BITS (57 CHARACTERS)
    >>> res = hash('aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfigj')
    >>> res
    >>> len(res)

    EXACTLY 504 BITS (63 CHARACTERS)
    >>> res = hash('aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfigjaleodi')
    >>> res
    >>> len(res)
    """
    # ORGANIZING ORIGINAL INPUT INTO BITS
    bit_string = utils.get_bits_as_string(input_string)
    bit_length = utils.get_number_of_bits_from_bit_string(bit_string)
    block_collection = BlockCollection(bit_string, bit_length)

    for block in block_collection.collection:
        curr_set_of_4 = []
        for i in range(64):
            curr_set_of_4.append(block.packaged_bits[i])
            if len(curr_set_of_4) == 4:
                full_str = "".join(curr_set_of_4)
                # REFERENCE: https://stackoverflow.com/questions/2072351/python-conversion-from-binary-string-
                # to-hexadecimal
                hexa_str = f'{int(full_str, 2):X}'
                if hexa_str == '0':
                    block.update_hexa_lst('00000000')
                elif len(hexa_str) < 8:
                    zeroes = (8 - len(hexa_str)) * '0'
                    block.update_hexa_lst(zeroes + hexa_str)
                else:
                    block.update_hexa_lst(hexa_str)
                curr_set_of_4 = []

    # Define the set of all k-values
    k_values = ['D76AA478',
                'E8C7B756',
                '242070DB',
                'C1BDCEEE',
                'f57c0faf',
                '4787C62A',
                'A8304613',
                'FD469501',
                '698098D8',
                '8B44F7AF',
                'FFFF5BB1',
                '895CD7BE',
                '6B901122',
                'FD987193',
                'A679438E',
                '49B40821',
                'F61E2562',
                'C040B340',
                '265E5A51',
                'E9B6C7AA',
                'D62F105D',
                '02441453',
                'D8A1E681',
                'E7D3FBC8',
                '21E1CDE6',
                'C33707D6',
                'F4D50D87',
                '455A14ED',
                'A9E3E905',
                'FCEFA3F8',
                '676F02D9',
                '8D2A4C8A',
                'FFFA3942',
                '8771F681',
                '699D6122',
                'FDE5380C',
                'A4BEEA44',
                '4BDECFA9',
                'F6BB4B60',
                'BEBFBC70',
                '289B7EC6',
                'EAA127FA',
                'D4EF3085',
                '04881D05',
                'D9D4D039',
                'E6DB99E5',
                '1FA27CF8',
                'C4AC5665',
                'F4292244',
                '432AFF97',
                'AB9423A7',
                'FC93A039',
                '655B59C3',
                '8F0CCC92',
                'FFEFF47D',
                '85845DD1',
                '6FA87E4F',
                'FE2CE6E0',
                'A3014314',
                '4E0811A1',
                'F7537E82',
                'BD3AF235',
                '2AD7D2BB',
                'EB86D391']

    # Initialization vectors
    a = '01234567'
    b = '89abcdef'
    c = 'fedcba98'
    d = '76543210'

    # Store originals for last modular operations (after 64 rounds)
    originals = [a, b, c, d]

    # Apply all block operations on each block (see diagram)
    for block in block_collection.collection:
        # ROUND 1 DATA LOADING

        # M inputs are sequential, copy block.hexa_lst
        round_one_m = block.hexa_lst[:]

        round_one_shift_map = {0: 7, 4: 7, 8: 7, 12: 7,
                               1: 12, 5: 12, 9: 12, 13: 12,
                               2: 17, 6: 17, 10: 17, 14: 17,
                               3: 22, 7: 22, 11: 22, 15: 22}

        # Output: 4 new initialization vectors (str) for Round 2 as new A, B, C, D
        round_one_output = _round_one(a, b, c, d, round_one_m, round_one_shift_map, k_values)


        # ROUND 2 DATA LOADING

        # M inputs loaded in the following order
        round_two_m_indices = [1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12]
        round_two_m = []

        for index in round_two_m_indices:
            round_two_m.append(round_one_m[index])

        # Initialization vectors
        a = round_one_output[0]
        b = round_one_output[1]
        c = round_one_output[2]
        d = round_one_output[3]

        round_two_shift_map = {0: 5, 4: 5, 8: 5, 12: 5,
                               1: 9, 5: 9, 9: 9, 13: 9,
                               2: 14, 6: 14, 10: 14, 14: 14,
                               3: 20, 7: 20, 11: 20, 15: 20}

        round_two_k_values = k_values[16:]

        # Output: 4 new initialization vectors (str) for Round 3 as new A, B, C, D
        round_two_output = _round_two(a, b, c, d, round_two_m, round_two_shift_map, round_two_k_values)


        # ROUND 3 DATA LOADING

        # M inputs loaded in the following order
        round_three_m_indices = [5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2]
        round_three_m = []

        for index in round_three_m_indices:
            round_three_m.append(round_one_m[index])

        # Initialization vectors
        a = round_two_output[0]
        b = round_two_output[1]
        c = round_two_output[2]
        d = round_two_output[3]

        round_three_shift_map = {0: 4, 4: 4, 8: 4, 12: 4,
                                 1: 11, 5: 11, 9: 11, 13: 11,
                                 2: 16, 6: 16, 10: 16, 14: 16,
                                 3: 13, 7: 13, 11: 13, 15: 13}

        round_three_k_values = round_two_k_values[16:]

        # Output: 4 new initialization vectors (str) for Round 4 as new A, B, C, D
        round_three_output = _round_three(a, b, c, d, round_three_m, round_three_shift_map, round_three_k_values)


        # ROUND 4 DATA LOADING

        # M inputs loaded in the following order
        round_four_m_indices = [0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9]
        round_four_m = []

        for index in round_four_m_indices:
            round_four_m.append(round_one_m[index])

        # Initialization vectors
        a = round_three_output[0]
        b = round_three_output[1]
        c = round_three_output[2]
        d = round_three_output[3]

        round_four_shift_map = {0: 6, 4: 6, 8: 6, 12: 6,
                                1: 10, 5: 10, 9: 10, 13: 10,
                                2: 15, 6: 15, 10: 15, 14: 15,
                                3: 21, 7: 21, 11: 21, 15: 21}

        round_four_k_values = round_three_k_values[16:]

        # Output: 4 new initialization vectors (str) for Round 4 as new A, B, C, D
        round_four_output = _round_four(a, b, c, d, round_four_m, round_four_shift_map, round_four_k_values)

        a = round_four_output[0]
        b = round_four_output[1]
        c = round_four_output[2]
        d = round_four_output[3]

        # RUN WRAP-UP OPERATIONS
        a = _wrap_up_operation(a, originals[0])
        b = _wrap_up_operation(b, originals[1])
        c = _wrap_up_operation(c, originals[2])
        d = _wrap_up_operation(d, originals[3])

    a = ('0' * (8 - len(a))) + a
    b = ('0' * (8 - len(b))) + b
    c = ('0' * (8 - len(c))) + c
    d = ('0' * (8 - len(d))) + d

    return a + b + c + d


def _round_one(a: str, b: str, c: str, d: str, m_values: list[str], shift_map: dict[int, int], k_values: list[str]) -> \
        tuple[str, str, str, str]:
    """
    Runs the one round of operations using the initialized values in the main, thereby executing each of the
    "red" boxes that must be run for each round (see diagram).
    """
    for i in range(16):
        f_output = _f_function(b, c, d)
        # Get the first operation box output to feed into the next box
        red_one_output = _red_one(f_output, a)
        # Using the first operation's output, get the second operation box output to feed into the next box
        # Here, we use one of the M-constants indexed based on the current iteration
        red_two_output = _red_two(red_one_output, m_values[i])
        # Using the second operation's output, get the third operation box output to feed into the next box
        # Here, we use one of the K-constants indexed based on the current iteration
        red_three_output = _red_three(red_two_output, k_values[i])
        # Apply a left-shift based on current shift amount from shift map
        left_shift_output = _left_shift(red_three_output, shift_map[i])
        red_four_output = _red_four(left_shift_output, b)
        # Assign appropriate a, b, c, and d for the next iteration (see diagram)
        a, b, c, d = d, red_four_output, b, c

    return (a, b, c, d)


def _f_function(b: str, c: str, d: str) -> str:
    """
    Takes in the B, C, and D initialization vectors and runs boolean algebra operation to return single str output.

    Sub-operation 1.
    """
    return (b and c) or (not b and d)


def _round_two(a: str, b: str, c: str, d: str, m_values: list[str], shift_map: dict[int, int], k_values: list[str]) -> \
        tuple[str, str, str, str]:
    """
    Runs the two round of operations using the initialized values in the main, thereby executing each of the
    "red" boxes that must be run for each round (see diagram).
    """
    for i in range(16):
        g_output = _g_function(b, c, d)
        # Get the first operation box output to feed into the next box
        red_one_output = _red_one(g_output, a)
        # Using the first operation's output, get the second operation box output to feed into the next box
        # Here, we use one of the M-constants indexed based on the current iteration
        red_two_output = _red_two(red_one_output, m_values[i])
        # Using the second operation's output, get the third operation box output to feed into the next box
        # Here, we use one of the K-constants indexed based on the current iteration
        red_three_output = _red_three(red_two_output, k_values[i])
        # Apply a left-shift based on current shift amount from shift map
        left_shift_output = _left_shift(red_three_output, shift_map[i])
        red_four_output = _red_four(left_shift_output, b)
        # Assign appropriate a, b, c, and d for the next iteration (see diagram)
        a, b, c, d = d, red_four_output, b, c

    return (a, b, c, d)


def _g_function(b: str, c: str, d: str) -> str:
    """
    Takes in the B, C, and D initialization vectors and runs boolean algebra operation to return single str output.

    Sub-operation 1.
    """
    return (b and d) or (c and not d)


def _round_three(a: str, b: str, c: str, d: str, m_values: list[str], shift_map: dict[int, int], k_values: list[str]) \
        -> tuple[str, str, str, str]:
    """
    Runs the third round of operations using the initialized values in the main, thereby executing each of the
    "red" boxes that must be run for each round (see diagram).
    """
    for i in range(16):
        h_output = _h_function(b, c, d)
        # Get the first operation box output to feed into the next box
        red_one_output = _red_one(h_output, a)
        # Using the first operation's output, get the second operation box output to feed into the next box
        # Here, we use one of the M-constants indexed based on the current iteration
        red_two_output = _red_two(red_one_output, m_values[i])
        # Using the second operation's output, get the third operation box output to feed into the next box
        # Here, we use one of the K-constants indexed based on the current iteration
        red_three_output = _red_three(red_two_output, k_values[i])
        # Apply a left-shift based on current shift amount from shift map
        left_shift_output = _left_shift(red_three_output, shift_map[i])
        red_four_output = _red_four(left_shift_output, b)
        # Assign appropriate a, b, c, and d for the next iteration (see diagram)
        a, b, c, d = d, red_four_output, b, c

    return (a, b, c, d)


def _h_function(b: str, c: str, d: str) -> str:
    """
    Takes in the B, C, and D initialization vectors and runs boolean algebra operation to return single str output.

    Sub-operation 1.
    >>> b = 'd5071367'
    >>> c = 'c058ade2'
    >>> d = '63c603d7'

    >>> e = _h_function(b, c, d)
    >>> e
    '7699bd52'
    """
    # CONVERT HEXADECIMAL TO NUMERIC FORM
    b = int(b, 16)
    c = int(c, 16)
    d = int(d, 16)

    result_as_hex_str = hex(b ^ c ^ d)
    return result_as_hex_str[2:]


def _round_four(a: str, b: str, c: str, d: str, m_values: list[str], shift_map: dict[int, int], k_values: list[str]) \
        -> tuple[str, str, str, str]:
    """
    Runs the fourth round of operations using the initialized values in the main, thereby executing each of the
    "red" boxes that must be run for each round (see diagram).
    """
    for i in range(16):
        i_output = _i_function(b, c, d)
        # Get the first operation box output to feed into the next box
        red_one_output = _red_one(i_output, a)
        # Using the first operation's output, get the second operation box output to feed into the next box
        # Here, we use one of the M-constants indexed based on the current iteration
        red_two_output = _red_two(red_one_output, m_values[i])
        # Using the second operation's output, get the third operation box output to feed into the next box
        # Here, we use one of the K-constants indexed based on the current iteration
        red_three_output = _red_three(red_two_output, k_values[i])
        # Apply a left-shift based on current shift amount from shift map
        left_shift_output = _left_shift(red_three_output, shift_map[i])
        red_four_output = _red_four(left_shift_output, b)
        # Assign appropriate a, b, c, and d for the next iteration (see diagram)
        a, b, c, d = d, red_four_output, b, c

    return (a, b, c, d)


def _i_function(b: str, c: str, d: str) -> str:
    """
    Takes in the B, C, and D initialization vectors and runs boolean algebra operation to return single str output.

    Sub-operation 1.
    >>> b = '7d502063'
    >>> c = '8b3d715d'
    >>> d = '1de3a739'

    >>> e = _i_function(b, c, d)
    >>> e
    'f66d513e'
    """
    # CONVERT HEXADECIMAL TO NUMERIC FORM
    b = int(b, 16)
    c = int(c, 16)
    d = int(d, 16)

    result_as_hex_str = hex(c ^ (b or not d))
    return result_as_hex_str[2:]


def _red_one(func_output: str, a: str) -> str:
    """
    Takes in the output from the respective round's Function (F, G, H, I) and combines with initialization vector A and
    applies modular addition to return a single str output. This is the first red modular arithmetic box.

    Sub-operation 2.

    >>> a = '01234567'
    >>> func_output = 'fedcba98'
    >>> ret = _red_one(func_output, a)
    >>> ret
    """
    x = int(a, 16)
    y = int(func_output, 16)
    z = 100000000

    return hex((x + y) % z)[2:]


def _red_two(red_one_output: str, m_value: str) -> str:
    """
    Takes in the output from the first red modular arithmetic box and combines with the current m_value and applies
    modular addition to return a single str output. This is the second red modular arithmetic box.

    Sub-operation 3.
    """
    x = int(m_value, 16)
    y = int(red_one_output, 16)
    z = 100000000

    return hex((x + y) % z)[2:]


def _red_three(red_two_output: str, k_value: str) -> str:
    """
    Takes in the output from the second red modular arithmetic box and combines with the current k_value and applies
    modular addition to return a single str output. This is the third red modular arithmetic box.

    Sub-operation 4.
    """
    x = int(k_value, 16)
    y = int(red_two_output, 16)
    z = 100000000

    return hex((x + y) % z)[2:]


def _left_shift(red_three_output: str, shift_val: int) -> str:
    """
    Takes in the output from the third red modular arithmetic box, converts it to binary, shifts the bit shift_val
    spaces to the left, then converts back to hexadecimal as a single str output.

    Sub-operation 5.
    >>> red_three_output = '2bd309f0'
    >>> shift_val = 7
    >>> output = _left_shift(red_three_output, shift_val)
    >>> output
    'e984f815'
    """
    # CONVERT HEXADECIMAL TO BINARY
    # Set up constants table; REFERENCE: https://stackoverflow.com/questions/1425493/convert-hex-to-binary
    HEX_TO_BINARY_CONVERSION_TABLE = {'0': '0000', '1': '0001', '2': '0010', '3': '0011', '4': '0100', '5': '0101',
                                      '6': '0110', '7': '0111', '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
                                      'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}

    binary_str = ''.join([HEX_TO_BINARY_CONVERSION_TABLE[char.lower()] for char in red_three_output])

    # APPLY SHIFT
    copy = binary_str[:shift_val]
    binary_str = binary_str[shift_val:] + copy

    # REFERENCE: https://stackoverflow.com/questions/2072351/python-conversion-from-binary-string-to-hexadecimal
    hexa_str = f'{int(binary_str, 2):X}'
    return hexa_str.lower()


def _red_four(left_shift_output: str, b: str) -> str:
    """
    Takes in the output from the left shift and combines with initialization vector B and applies
    modular addition to return a single str output. This is the fourth red modular arithmetic box.

    Sub-operation 6.
    """
    x = int(b, 16)
    y = int(left_shift_output, 16)
    z = 100000000

    return hex((x + y) % z)[2:]


def _wrap_up_operation(final_output: str, oiv: str) -> str:
    """
    Takes in the final output (one vector at a time) from all 64 operations (4 rounds) and combines with ORIGINAL
    respective initialization vector and applies modular addition to return a single str output.

    FINAL OPERATION PRE-VECTOR-CONCATENATION.
    """
    x = int(final_output, 16)
    y = int(oiv, 16)
    z = 100000000

    return hex((x + y) % z)[2:]
