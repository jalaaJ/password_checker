import requests
import hashlib
import sys

# using this function, we return the response from the api
def request_api_data(query_chars):
    # first, we get the url of the api
    url = 'https://api.pwnedpasswords.com/range/' + query_chars
    # then, we request the data and get a response which contains it
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching the data: {res.status_code}', "Check the API!")
    else:
        return res


# here, we want to check our hashed password against all of the hashed ones
def count_pass_leaks(hashes, hash_to_check):
    # we can use tuple comprehension
    # here, we get back a generator object which we can loop through
    # however, we need to split the lines that we get so we could split each line!
    hashes = (line.split(':') for line in hashes.text.splitlines())
    # the h stands for the tail hashes that we get back
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # here, we use the hashlib module to encode and hash our password with sha1 alg
    # and this is just a standard way to hash and encode a password
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # here, we only want to return the first 5 chars
    first5chars, tail = sha1_password[:5], sha1_password[5:]
    response = request_api_data(first5chars)
    return count_pass_leaks(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was pwned {count} times! It's safer to change it.")
        else:
            print("Your password wasn't pwned! You can safely keep it.")


main(sys.argv[1:])



