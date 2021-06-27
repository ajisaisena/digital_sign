from sign_lib import *
from sympy import randprime
from random import randint


def generate_key():
    """
    Schnorr 生成元和素数对生成
    :return: list[p,q,g]
    """
    flag = 1
    while flag == 1:
        q = randprime(2 ** 160, 2 ** 161)
        for i in range(100):
            r = 2 * randint(2 ** 863, 2 ** 864)
            p = r * q + 1
            if is_prime(p):
                flag = 0
                break
    h = randint(1, p - 1)
    while fast_pow(h, r, p) == 1:
        h = randint(1, p - 1)
    g = fast_pow(h, r, p)
    return [p, q, g]


def schnorr(p, q, alpha, mes):
    """
    schnorr签名函数
    :param p: 素数p,int
    :param q: 素数q,int
    :param alpha: 生成元/alpha,int
    :param mes: 签名明文,str
    :return: schnorr签名结果及其公钥，(p,q,alpha,v),(e,y)
    """
    s = randint(1, q - 1)
    v = fast_pow(get_inv(alpha, p), s, p)
    r = randint(1, q - 1)
    x = fast_pow(alpha, r, p)
    x_byte = align(x)
    e = int(sha1_hash(mes.encode() + x_byte).hex(), 16)
    y = (r + s * e) % q
    sign = (e, y)
    pub = (p, q, alpha, v)
    return pub, sign


def schnorr_verify(mes, pub, sign):
    """
    schnorr签名验证函数
    :param mes: 验证明文
    :param pub: 公钥,(p,q,alpha,v)
    :param sign: 签名,(e,y)
    :return: 签名成功(True),失败(False)
    """
    p, q, alpha, v = pub
    e, y = sign
    x = (fast_pow(alpha, y, p) * fast_pow(v, e, p)) % p
    x_byte = align(x)
    return e == int(sha1_hash(mes.encode() + x_byte).hex(), 16)


def main():
    p, q, g = generate_key()
    pub, sign = schnorr(p, q, g, 'heyguys')
    print(schnorr_verify('heyguys', pub, sign))


if __name__ == "__main__":
    main()
