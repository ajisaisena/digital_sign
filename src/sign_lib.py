from cryptography.hazmat.primitives import hashes
from random import randint


def fast_pow(x, n, m):
    """
    快速幂求解x^n%m
    :param x: 底数x, int
    :param n: 指数n, int
    :param m: 模数m, int
    :return: 计算结果, int
    """
    result = 1
    while n > 0:
        if n % 2 == 1:
            result = result * x % m
        x = x * x % m
        n = n // 2
    return result % m


def extended_gcd(a, b):
    """
    扩展欧几里得算法
    :param a: 参数a, int
    :param b: 参数b, int
    :return: b在a下的逆元
    """
    if a[2] == 0:
        return b[1]
    else:
        q = b[2] // a[2]
        t1 = b[0] - q * a[0]
        t2 = b[1] - q * a[1]
        t3 = b[2] - q * a[2]
        return extended_gcd([t1, t2, t3], a)


def get_inv(num, mod):
    """
    逆元求解包装接口
    :param num: 求的逆元参数num, int
    :param mod: 模数mod, int
    :return: num在mod下的逆元, int
    """
    nums = [0, 1, num]
    mods = [1, 0, mod]
    return extended_gcd(nums, mods)


def sha1_hash(mes):
    digest = hashes.Hash(hashes.SHA1())
    digest.update(mes)
    return digest.finalize()


def gcd(a, b):
    """
    最大公因数求解函数
    :param a: 参数a, int
    :param b: 参数b, int
    :return: a和b的最大公因数，int
    """
    return a if b == 0 else gcd(b, a % b)


def miller_rabin(p):
    """
    miller_rabin素性检测
    :param p: 用于检测的素数p, int
    :return: 是素数(True)或不是素数(False)
    """
    random_time = 10  # 用一个很小的数亦可；这个数是随手打的
    if p < 3:
        return p == 2  # 先进行2判定
    q = p - 1
    t = 0
    while q % 2 == 0:  # 先把q和t求好
        q //= 2
        t += 1
    for i in range(1, random_time + 1):  # 进行random_time次检测
        a = randint(2, p - 1)
        v = fast_pow(a, q, p)
        if v == 1 or v == p - 1:  # 进行1或-1判定
            continue
        for j in range(t + 1):
            v = v * v % p
            if v == p - 1:
                break
        else:
            return False
    return True


def is_prime(p):
    """
    素性检测接口
    :param p: 用于检测的参数p, int
    :return: 是素数(True)或不是素数(False)
    """
    return miller_rabin(p)


def bytes_xor(a, b, lens=None):
    """
    字节串异或函数
    :param a: 字节串a,bytes
    :param b: 字节串b,bytes
    :param lens: 指定输出长度,以字节计算,int
    :return: 字节串异或结果
    """
    return align(int(a.hex(), 16) ^ int(b.hex(), 16), lens)


def align(num, lens=None):
    """
    字节对齐函数
    :param num: 用于对其的值,int
    :param lens: 指定输出长度,int
    :return: 字节对齐结果
    """
    if lens is None:
        string = '0' + hex(num)[2:] if len(hex(num)) % 2 != 0 else hex(num)[2:]
        return bytes.fromhex(string)
    else:
        string = '{:0{}x}'.format(num, 2 * lens)
        return bytes.fromhex(string)
