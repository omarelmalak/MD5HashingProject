import pytest

import hash_main
from login_system import LoginSystem


def test_login_system():
    """
    Test that the login system's account creation and password validation are functioning as intended (test matching
    hashes as well).
    """
    system = LoginSystem()

    system.create_new_account("guest", "a")
    password = "a"
    assert system.validate_password("guest", password)

    hashed_input_password = hash_main.hash(password)
    hashed_true_password = system.get_username_and_hash_pair("guest")[1]

    assert hashed_input_password == hashed_true_password

    system.create_new_account("guest2", "ab")
    password = "ab"
    assert system.validate_password("guest2", password)

    hashed_input_password = hash_main.hash(password)
    hashed_other_password = hash_main.hash("ab")
    hashed_true_password = system.get_username_and_hash_pair("guest2")[1]

    assert hashed_input_password == hashed_true_password
    assert hashed_other_password != hashed_true_password

    system.create_new_account("guest3", "abc")
    password = "abc"
    assert system.validate_password("guest3", password)

    hashed_input_password = hash_main.hash(password)
    hashed_other_password1 = hash_main.hash("a")
    hashed_other_password2 = hash_main.hash("ab")
    hashed_true_password = system.get_username_and_hash_pair("guest3")[1]

    assert hashed_input_password == hashed_true_password
    assert hashed_other_password1 != hashed_true_password
    assert hashed_other_password2 != hashed_true_password


def test_equal_length():
    """
    Test that all hashes are of equal length (exactly 32 characters each).
    """

    # Test on the following common + edge cases...
    test_cases = []

    # ARTICLE EXAMPLE
    CASE_ONE = 'They are deterministic'
    test_cases.append(CASE_ONE)

    # SINGLE ELEMENT EXAMPLE (LOWERCASE)
    CASE_TWO = 'a'
    test_cases.append(CASE_TWO)

    # SINGLE ELEMENT EXAMPLE (UPPERCASE)
    CASE_THREE = 'A'
    test_cases.append(CASE_THREE)

    # OVER 64-bit LENGTH (9, 223, 372, 036, 854, 775, 808 CHARACTERS)
    CASE_FOUR = 'a' * 1000
    test_cases.append(CASE_FOUR)

    # EXACTLY 1560 (520 * 3) BITS(195 CHARACTERS)
    CASE_FIVE = 'mgmbcihkbcsbswccfkfqpkrxfuxbvnjuwnteqnkedqcbastulcajartugjvahbwwbeqbuixfxbhwevohbyqipnzgvxqhyzqrkdriucnqbcvjcotjbhwxnznodrvkmpdtwxdhbkbdkwuvnfwrbfccfchpachovajyvdoauutsbeibxbnlwhpripoaslqjeobotbo'
    test_cases.append(CASE_FIVE)

    # EXACTLY 512 BITS (64 CHARACTERS)
    CASE_SIX = 'aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfigjaleodif'
    test_cases.append(CASE_SIX)

    # EXACTLY 0 BITS (0 CHARACTERS; EMPTY STRING)
    CASE_SEVEN = ''
    test_cases.append(CASE_SEVEN)

    # EXACTLY 8 BITS (1 CHARACTER)
    CASE_EIGHT = 'h'
    test_cases.append(CASE_EIGHT)

    # EXACTLY 448 BITS (56 CHARACTERS)
    CASE_NINE = 'aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfig'
    test_cases.append(CASE_NINE)

    # EXACTLY 456 BITS (57 CHARACTERS)
    CASE_TEN = 'aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfigj'
    test_cases.append(CASE_TEN)

    # EXACTLY 504 BITS (63 CHARACTERS)
    CASE_ELEVEN = 'aitufiyehaidpeyufidopakri1234rpalisojnemryafhxcgrtyabfigjaleodi'
    test_cases.append(CASE_ELEVEN)

    for case in test_cases:
        hashed_string = hash_main.hash(case)
        assert len(hashed_string) == 32


def test_case_sensitivity():
    """
    Test that passwords are case sensitive.
    """

    pass1 = "abCdef"
    pass2 = "abcdef"

    system = LoginSystem()

    system.create_new_account("guest", pass1)

    assert system.validate_password("guest", pass1) == True
    assert system.validate_password("guest", pass2) == False


def test_incorrect_password():
    """
    Test that an incorrect password does NOT grant access to the account via its hash, even if the inputted password
    is very similar.
    """
    system = LoginSystem()

    system.create_new_account("guest", "abc")
    password = "ab"
    assert system.validate_password("guest", password) == False
    password = "ABC"
    assert system.validate_password("guest", password) == False
    password = "abcd"
    assert system.validate_password("guest", password) == False
    password = "abc "
    assert system.validate_password("guest", password) == False
    password = " abc"
    assert system.validate_password("guest", password) == False


def test_correct_user():
    """
    Test that inputting a correct password for a different user than the one intended does NOT grant access to the
    account.
    """
    system = LoginSystem()

    system.create_new_account("guest", "abc")
    password = "abc"
    assert system.validate_password("guest", password)

    system.create_new_account("guest2", "a")
    assert system.validate_password("guest", "abc")
    assert system.validate_password("guest2", "abc") == False

    assert system.validate_password("guest", "a") == False
    assert system.validate_password("guest2", "a")


pytest.main(["test_vowels.py"])
