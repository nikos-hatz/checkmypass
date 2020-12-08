import requests
import hashlib
import sys

'''This password checker uses the API from the website pwnedpasswords.com in which you can check if your password 
has been hacked.You can use this program if you dont want to type your password in the website and check it locally in 
your computer.It checks if the password has been hacked by requesting the first 5 letters of the hashed password
and the rest is being checked in your computer
'''


def request_api_data(query_char):                                            #
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):                          #Check how many times the password has been hacked
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()   #Hash your password using sha1 hash function
    first5_char, tail = sha1password[:5], sha1password[5:]                      #Take the first 5 letter of the hashed password
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 0


if __name__ == '__main__':
    pass_input = [input('please type your password \n')]
    sys.exit(main(pass_input))
