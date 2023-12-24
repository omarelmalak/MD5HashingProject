# MD5HashingProject

## An implementation of the MD5 Hashing algorithm for efficient password validation and security in Python.

This project was built using an algorithm reference provided by Comparitech (https://www.comparitech.com/blog/information-security/md5-algorithm-with-examples/) to manually implement the MD5 Hashing Algorithm in Python. This functionality not only provides an effective and safe way to validate passwords without conretely storing them on-site, but can also be modified to be used for other applications such as a randomized password generator.

For this project, the focus was placed on developing a login system that relies on the MD5 Hashing algorithm to construct a hash table of all accounts stored within the database and their respective hashes. Then, upon a user login attempt, the system validates the password by converting the inputted password to a hash and performing a comparison on this hash with the respective entry in the hash table. 

The purpose of this project is to demonstrate the ability to one-way hash and validate passwords, making it severely challenging to maliciously reverse engineer a hash to a password in the case of a data leak. This is done by implementing the multi-layered and multi-round MD5 Hashing Algorithm that is deterministic but effective in protecting passwords by storing them indirectly.

## Visual Representation


## Project Cloning + Personal Use
As previously mentioned, the MD5 Hashing Algorithm is effective in the realm of password validation, but also has other use cases. The login_system.py file is an example of a system that could implement the algorithm, but feel free to create new systems with the following import at the top of the Python file: import hash_main. 
