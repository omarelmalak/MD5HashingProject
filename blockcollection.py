from block import Block, CompleteBlock, MidBlock, PaddedBlock


class BlockCollection:
    """
    An organized collection of at least one 512-bit Block objects used to model a padded input as per MD5 format.

    === REPRESENTATION INVARIANTS ===
    len(self.collection) >= 1
    """

    collection: list[Block]

    def __init__(self, bit_string: str, bit_length: int) -> None:
        """
        Creates a BlockCollection instance.
        """
        self.collection = []

        self._populate_collection(bit_string, bit_length, bit_length)

    def _populate_collection(self, bit_string: str, bit_length: int, fixed_bit_length: int) -> None:
        """
        A "factory-esque" method that creates the appropriate Block type instantiations
        to add to a collection of 512-bit blocks that comprise an inputted password.
        """
        # Base case 1
        if bit_length < 448:
            self.collection.append(PaddedBlock(bit_string, bit_length, fixed_bit_length))
        # Base case 2
        elif bit_length == 448:
            self.collection.append(MidBlock(bit_string, bit_length))
            self.collection.append(PaddedBlock('', 0, fixed_bit_length))
        # Base case 3
        elif bit_length >= 449 and bit_length <= 511:
            self.collection.append(MidBlock(bit_string, bit_length))
            self.collection.append(PaddedBlock('', 0, fixed_bit_length))
        else:
            self.collection.append(CompleteBlock(bit_string))
            # Apply recursive step on the next bits after the rightmost 512 bits have been used on a CompleteBlock
            self._populate_collection(bit_string[:-576], bit_length - 512, fixed_bit_length)

