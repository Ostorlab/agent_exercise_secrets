import random

def logging(url, api_key):
    print('Connecting...')
    print('Connected successfully !')


def connect(url):
    api_key1 = '4242a-a4242-420l-f2df493465a1'
    api_key2 = "5729-4ba9-8c08-f2df493465a1"
    random_choice = bool(random.getrandbits(1))
    api_key = api_key1 if random_choice is True else api_key2

    logging(url, api_key)


if __name__ == '__main__':
    connect('https://www.dummy.com/')


