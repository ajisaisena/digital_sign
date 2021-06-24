from random import randint
from sign_lib import *


def elgamal(alpha, q, mes):
    x = randint(2, q-2)
    y_a = fast_pow(alpha, x, q)
    m = int(hash(mes.encode()).hex(), 16)
    k = q-1
    while gcd(k, q-1) != 1:
        k = randint(1, q-2)
    s_1 = fast_pow(alpha, k, q)
    k_inv = get_inv(k, q-1)
    s_2 = (k_inv*(m-x*s_1)) % (q-1)
    pub = (q, alpha, y_a)
    sign = (s_1, s_2)
    return (pub, sign)


def elgamal_verify(mes, pub, sign):
    q, alpha, y_a = pub
    s_1, s_2 = sign
    m = int(hash(mes.encode()).hex(), 16)
    v_1 = fast_pow(alpha, m, q)
    v_2 = (fast_pow(y_a, s_1, q)*fast_pow(s_1, s_2, q)) % q
    return v_1 == v_2


def main():
    pub, sign = elgamal(10, 19, 'hey')
    print(elgamal_verify('hey', pub, sign))


if __name__ == '__main__':
    main()
