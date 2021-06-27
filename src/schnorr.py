from sign_lib import *
from sympy import randprime
from random import randint


def generate_key():
    flag = 1
    while flag == 1:
        q = randprime(2 ** 160, 2 ** 161)
        for i in range(100):
            r = 2*randint(2**863, 2**864)
            p = r*q+1
            if is_prime(p):
                flag = 0
                break
    h = randint(1, p-1)
    while fast_pow(h, r, p) == 1:
        h = randint(1, p-1)
    g = fast_pow(h, r, p)
    return [p, q, g]


def schnorr(p, q, alpha, mes):
    s = randint(1, q-1)
    v = fast_pow(get_inv(alpha, p), s, p)
    r = randint(1, q-1)
    x = fast_pow(alpha, r, p)
    x_byte = align(x)
    e = int(hash(mes.encode()+x_byte).hex(), 16)
    y = (r+s*e) % q
    sign = (e, y)
    pub = (p, q, alpha, v)
    return (pub, sign)


def schnorr_verify(mes, pub, sign):
    p, q, alpha, v = pub
    e, y = sign
    x = (fast_pow(alpha, y, p)*fast_pow(v, e, p)) % p
    x_byte = align(x)
    return e == int(hash(mes.encode()+x_byte).hex(), 16)


def main():
    p, q, g = generate_key()
    pub, sign = schnorr(p, q, g, 'heyguys')
    print(schnorr_verify('heyguys', pub, sign))


if __name__ == "__main__":
    main()
