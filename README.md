# MD5HashingProject

An implementation of the MD5 Hashing algorithm for efficient password validation and security in Python.

## Project Overview

This project was built using an algorithm reference provided by Comparitech (https://www.comparitech.com/blog/information-security/md5-algorithm-with-examples/) to manually implement the MD5 Hashing Algorithm in Python. This functionality not only provides an effective and safe way to validate passwords without conretely storing them on-site, but can also be modified to be used for other applications such as a randomized password generator.

For this project, the focus was placed on developing a login system that relies on the MD5 Hashing algorithm to construct a hash table of all accounts stored within the database and their respective hashes. Then, upon a user login attempt, the system validates the password by converting the inputted password to a hash and performing a comparison on this hash with the respective entry in the hash table.

## Project Purpose

The purpose of this project is to demonstrate the ability to one-way hash and validate passwords, making it severely challenging to maliciously reverse engineer a hash to a password in the case of a data leak. This is done by implementing the multi-layered and multi-round MD5 Hashing Algorithm that is deterministic but effective in protecting passwords by storing them indirectly.

## Step-by-Step Hashing Process Brief + Visual Examples/Representations
Please note that some of the following diagrams are supplied by Comparitech, but I found them useful in guiding the logic of my algorithm and thereby desgined the functions in my code to modularize the problem based on the outline they provide. Thus, I have added how the diagrams translate to the different functions in the code as extra text boxes.

In the spirit of modularizing the algorithm, the following step-by-step brief leverages the different functions to break down the problem of hashing a password:

1. First, upon receiving a password input, the algorithm breaks it down into bits (a binary representation) using the functions in utils.py.

2. The algorithm then, depending on the length of the bit string, recursively constructs 512-bit block representations comprised of padded binary bit strings that make up the password. Such Block objects are then stored in an instantiated BlockCollection object, allowing us to traverse the blocks of bits in the next step.
<img width="332" alt="Screenshot 2023-12-24 at 10 38 54 PM" src="https://github.com/omarelmalak/MD5HashingProject/assets/140688960/c417027e-e931-4e16-b3fc-e20e018765a2">


3. Next, the algorithm will create the MD5 initialization vectors A, B, C, and D. These vectors will go through four layers of the algorithm per block (denoted by the green box with the label "512-bit message block, M", this corresponds with the green block that will be inputted from the previous step).
<img width="629" alt="Screenshot 2023-12-24 at 11 01 35 PM" src="https://github.com/omarelmalak/MD5HashingProject/assets/140688960/9a83e0c0-5d0c-46cb-9fb6-a5babd424dfd">

Courtesy of Comparitech, function annotations added by me for greater clarity with respect to my Python implementation.


4. Each of the layers in the above diagram involve performing a set of operations using a specified collection of K-constants, M-values (each is a word-length [32-bit] substring of the green block from earlier) and shift values from the constant shift map. Each layer will iterate precisely 16 times, feeding the A, B, C, and D vectors through the end of each iteration to the beginning of the next one (and when the layer is done, from the end of that layer to the beginning of the next one). The following is a zoom-in of one such layer:
<img width="743" alt="Screenshot 2023-12-24 at 11 02 03 PM" src="https://github.com/omarelmalak/MD5HashingProject/assets/140688960/99fa3ce0-01d0-46c0-b6c7-2d312ef5aea0">

Courtesy of Comparitech, function annotations added by me for greater clarity with respect to my Python implementation.

5. Finally, after going through all the blocks and feeding the resultant A, B, C, and D vectors at the end of each block to the beginning of the process of the next one, the algorithm performs a wrap-up operation to put the vectors together into one, standardized 32-bit hash that is returned. The result? A one-way encrypted password that gets stored and can be accessed from a hash table for many applications, for instance a login database!
<img width="572" alt="Screenshot 2023-12-24 at 8 38 25 PM" src="https://github.com/omarelmalak/MD5HashingProject/assets/140688960/2e9aa064-f32e-4ce6-8511-8bb4599cebbe">



This brief overview explains the general structure of how the algorithm works. Within the code, each function is documented to support the description indicated in the Comparitech article. Please refer to the article link for a more in-depth description and the in-line and documentation comments in the code for support.

## Project Forking + Modification
As previously mentioned, the MD5 Hashing Algorithm is effective in the realm of password validation, but also has other use cases. The login_system.py file is an example of a system that could implement the algorithm, but feel free to create new systems using the MD5 Hashing Algorithm as a base with the following import at the top of the Python file: import hash_main. 
