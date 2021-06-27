from sign_lib import *


def elgamal(alpha, q, mes):
    """
    elgamal签名方法
    :param alpha: 生成元,int
    :param q: 素数q,int
    :param mes: 签名明文,str
    :return: elgamal公钥和签名对,(q,alpha,y_a),(s_1, s_2)
    """
    x = randint(2, q - 2)
    y_a = fast_pow(alpha, x, q)
    m = int(sha1_hash(mes.encode()).hex(), 16)
    k = q - 1
    while gcd(k, q - 1) != 1:
        k = randint(1, q - 2)
    s_1 = fast_pow(alpha, k, q)
    k_inv = get_inv(k, q - 1)
    s_2 = (k_inv * (m - x * s_1)) % (q - 1)
    pub = (q, alpha, y_a)
    sign = (s_1, s_2)
    return pub, sign


def elgamal_verify(mes, pub, sign):
    """
    elgamal签名验证
    :param mes: 签名明文,str
    :param pub: 公钥(q,alpha,y_a)
    :param sign: 签名(s_1, s_2)
    :return: 验证成功(True),失败(False)
    """
    q, alpha, y_a = pub
    s_1, s_2 = sign
    m = int(sha1_hash(mes.encode()).hex(), 16)
    v_1 = fast_pow(alpha, m, q)
    v_2 = (fast_pow(y_a, s_1, q) * fast_pow(s_1, s_2, q)) % q
    return v_1 == v_2


def main():
    pub, sign = elgamal(10, 19, 'hey')
    print(elgamal_verify('hey', pub, sign))


if __name__ == '__main__':
    main()
