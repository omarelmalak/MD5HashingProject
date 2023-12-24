import utils

class Block:
    """
    Represents ONE 512-bit Block used in a BlockCollection to model a padded input as per MD5 format.

    ABSTRACT CLASS INHERITED BY CompletedBlock, MidBlock, and PaddedBlock.

    === REPRESENTATION INVARIANTS ===
    len(packaged_bits) == 64
    """

    packaged_bits: list[str]
    hexa_lst: list[str]

    def __init__(self, bit_string: str) -> None:
        """
        Creates a Block instance.

        Note that this is an ABSTRACT class, and should not be instantiable.
        """
        raise NotImplementedError

    def update_hexa_lst(self, hexa_str: str) -> None:
        """
        Appends the hexa_str inputted to the hexa_lst instance attribute.
        """
        self.hexa_lst.append(hexa_str)


    def __str__(self) -> str:
        """
        Returns an 8 x 8 box representation of a Block, containing bit strings of size 8 bits.
        """
        counter = 0
        ret_str = ''
        for bit_string in self.packaged_bits:
            if counter == 8:
                ret_str += '\n'
                counter = 0
            ret_str += bit_string + ' '
            counter += 1
        return ret_str




class CompleteBlock(Block):
    """
    Represents ONE 512-bit Block with NO PADDING (pure input data).

    === REPRESENTATION INVARIANTS ===
    Exactly 512 bits must be passed in through the string representation bit_string (bit_length == 512).
    """

    packaged_bits: list[str]
    # HEXA NOT UPDATED UNTIL AFTER INITIALIZATION PROCESS IS COMPLETE
    hexa_lst: list[str]

    def __init__(self, bit_string: str) -> None:
        """
        Creates a CompleteBlock instance.
        """
        bit_lst = bit_string.split(' ')
        self.packaged_bits = bit_lst[-64:]

        self.hexa_lst = []


class MidBlock(Block):
    """
    Represents ONE 512-bit Block with MEDIUM PADDING (just a 1 followed by 0s; no length at the end).

    === REPRESENTATION INVARIANTS ===
    Between 448 and 511 (inclusive) bits must be passed in through the string representation bit_string
    (448 <= bit_length <= 511).
    """

    packaged_bits: list[str]
    number_of_zeros_to_512: int
    hexa_lst: list[str]

    def __init__(self, bit_string: str, bit_length: int) -> None:
        """
        Creates a MidBlock instance.
        """
        bit_lst = bit_string.split(' ')
        self.packaged_bits = bit_lst[:]
        self.number_of_zeros_to_512 = 512 - 1 - bit_length
        self.packaged_bits.append('10000000')
        self.packaged_bits.extend(['00000000' for i in range((self.number_of_zeros_to_512 - 7) // 8)])

        self.hexa_lst = []


class PaddedBlock(Block):
    """
    Represents ONE 512-bit Block that contains at least one bit of padding.

    === REPRESENTATION INVARIANTS ===
    Up to 447 bits must be passed in through the string representation bit_string (bit_length <= 447).
    """

    packaged_bits: list[str]
    number_of_zeros_to_448: int
    bit_length: int
    hexa_lst: list[str]

    def __init__(self, bit_string: str, bit_length: int, fixed_bit_length: int) -> None:
        """
        Creates a PaddedBlock instance.
        """
        self.packaged_bits = []
        self.bit_length = bit_length
        self.number_of_zeros_to_448 = 448 - 1 - bit_length
        self._populate_packaged_bits(bit_string, fixed_bit_length)

        self.hexa_lst = []

    def _populate_packaged_bits(self, bit_string: str, fixed_bit_length: int) -> None:
        """
        Populate packaged bits depending on length of bit_string.
        """
        if bit_string != '':
            bit_lst = bit_string.split(' ')
            self.packaged_bits = bit_lst[:]

        if self.bit_length == 0:
            self.packaged_bits.append('00000000')
        else:
            self.packaged_bits.append('10000000')

        self.packaged_bits.extend(['00000000' for i in range((self.number_of_zeros_to_448 - 7) // 8)])

        length_as_bytes = utils.int_to_bytes(fixed_bit_length)
        length_as_bits_lst = [utils.byte_to_bits(byte) for byte in length_as_bytes]

        if len(length_as_bits_lst) * 8 >= 64:
            for i in range(-8, 0, 1):
                self.packaged_bits.append(length_as_bits_lst[i])
        else:
            self.packaged_bits.extend(['00000000' for i in range(8 - len(length_as_bits_lst))])
            self.packaged_bits.extend(length_as_bits_lst)


