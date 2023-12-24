import hash_main

class LoginSystem:
    """
    A simple login system used to demonstrate the application of MD5 hashing's effect on securing login systems.


    This system protects the password from a leak. This is because the account is not accessible solely
    using the hash collected from the hash_map in a data leak. The account is no longer susceptible as an attempt
    to input this hash as a "password" will result in another hash that is different from the hash in the system.

    Although deterministic, the MD5 hashing algorithm is designed to be difficult to reverse-engineer due to the
    multi-layered algorithmic approach to breaking down a password into a 32-character hash.
    """
    hash_map: dict[str, str]

    def __init__(self) -> None:
        self.hash_map = {}

    def check_existing_username(self, username: str) -> bool:
        """
        Checks if the username already exists in the login system.

        Returns true if the username exists and false if the username does not exist.
        """
        return username in self.hash_map

    def validate_password(self, username: str, password: str) -> bool:
        """
        Validates that a username and its inputted password matches with the hashed password tied to the username in
        the system.

        Returns true if the inputted password's hash matches the hash tied to the username in the system, otherwise
        returns false.

        PRECONDITION: Username/password combination exists in the login system.
        """
        hashed_password = hash_main.hash(password)
        return self.hash_map[username] == hashed_password

    def create_new_account(self, username: str, password: str) -> None:
        """
        Creates a new account with the appropriate password, but the original password itself is NOT saved.
        """
        hashed_password = hash_main.hash(password)
        self.hash_map[username] = hashed_password

    def get_username_and_hash_pair(self, username: str) -> tuple[str, str]:
        """
        Returns a tuple pair in the form (username, hashed password) upon being provided a username.
        """
        return username, self.hash_map[username]

    def is_empty(self) -> bool:
        """
        Returns true if the database of the login system is empty, and false otherwise (if it is populated).
        """
        return len(self.hash_map.keys()) == 0

    def print_database(self) -> None:
        """
        Print the login system database in a table-style format displaying all the stored username-hash pairs.

        PRECONDITION: len(username) <= 32 and len(hash) == 32 for all username/hash pairs.
        """
        print("-" * 71)
        title_padding_username = 12 * " "
        title_padding_hash = 14 * " "
        print("| " + title_padding_username + "USERNAME" + title_padding_username + " | " + title_padding_hash + "HASH"
              + title_padding_hash + " |")
        print("-" * 71)
        for key in self.hash_map:
            if len(key) % 2 == 0:
                left_padding = " " * ((32 - len(key)) // 2)
                right_padding = left_padding
            else:
                left_padding = " " * ((32 - len(key)) // 2)
                right_padding = left_padding + " "

            iteration_str = "| " + left_padding + key + right_padding + " | " + self.hash_map[key] + " |"
            print(iteration_str)
        print("-" * 71)

if __name__ == '__main__':
    # Simulate a username/password login and display hash comparisons
    cont = 'y'
    system = LoginSystem()
    while cont == 'y':
        decision = input('Would you like to create an account, log in, or print the current database (c/l/d)? ')
        if decision.lower() == 'c':
            print('Great! Let\'s create your account.')
            username = input('Input your username: ')
            if len(username) > 32:
                print("The username is too long (max 32 characters).")
            else:
                if system.check_existing_username(username):
                    print('Username already exists. Please retry.')
                else:
                    password = input('Enter password: ')
                    system.create_new_account(username, password)
        elif decision.lower() == 'l':
            username = input('Enter username: ')
            if not system.check_existing_username(username):
                print('No account with such username. Please retry.')
            else:
                password = input('Enter password: ')
                if system.validate_password(username, password):
                    print('True Password hash: ' + system.get_username_and_hash_pair(username)[1])
                    print('Your inputted password hash: ' + hash_main.hash(password))
                    print('Success (hashes match)! Welcome to your account.')
                    print()
                else:
                    print('True Password hash: ' + system.get_username_and_hash_pair(username)[1])
                    print('Your inputted password hash: ' + hash_main.hash(password))
                    print('Incorrect password (hashes do NOT match). Please retry.')
                    print()
        elif decision.lower() == "d":
            if system.is_empty():
                print("Empty database.")
            else:
                system.print_database()
        else:
            print('Invalid input.')

        cont = input('Would you like to continue (y/n)? ').lower()
