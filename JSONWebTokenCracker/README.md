# JWT Crack
A tool used to perform a threaded dictionary attack against the secret keyword of HMAC signed tokens

Usage: JWTCrack.py [-h] [-a {HS256,HS384,HS512}] [-t THREADS] encoded_jwt wordlist

positional arguments:
  encoded_jwt           Base64 Encoded JWT String
  wordlist              Dictionary wordlist file used to bruteforce the JWT

optional arguments:
  -h, --help            show this help message and exit
  -a {HS256,HS384,HS512}, --algorithm {HS256,HS384,HS512}
                        HMAC Algorithm (default: HS256)
  -t THREADS, --threads THREADS
                        Number of threads (default: 8)
