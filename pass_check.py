import requests
import hashlib
import sys

# Receive data from api
def req_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check api and try again')
    return res

# Spliting hashed data on hash and how many times password is in api memory 
def get_pass_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Process of hashing data and spliting hashed method in two pieces
def pwned_api_check(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    response = req_api_data(first5_char)
    return get_pass_leaks_count(response, tail)

# Just looping through results and printing 
def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times')
        else:
            print(f'{password} was not found')
    return 'DONE!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
