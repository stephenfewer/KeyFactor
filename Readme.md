About
=====

A very basic example in factoring _tiny_ RSA public keys in order to generate a corresponding RSA private key.

Usage
=====

1. Generate a new RSA private key (With a tiny key size)
>openssl genrsa -out private.rsa 96

2. Extract the public key from the new private key (In PEM format so KeyFactor can read it)
>openssl rsa -in private.rsa -out public.rsa -pubout -outform PEM

3. Create a text file with the data to encrypt. We have to use a small plaintext due to the tiny key size, e.g. 96 bit keysize is a max of 12 bytes plaintext (96/8 = 12).
>echo 0123456789! > plaintext.txt

4. Encrypt the data with the public key so only the private key may decrypt it
>openssl rsautl -in plaintext.txt -out ciphertext.txt -inkey public.rsa -pubin -raw

5. Use the public key to create a new private key (About ~4 minutes for a 96 bit key)
>ruby KeyFactor.rb -verbose -public public.rsa -private solved_private.rsa

6. Decrypt the data with the newly found private key
>openssl rsautl -decrypt -in ciphertext.txt -inkey solved_private.rsa -raw

License
=======

The source code is available under the GPLv3 license, please see the included file gpl-3.0.txt for details.
