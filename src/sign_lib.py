from cryptography.hazmat.primitives import hashes


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


def hash(mes):
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
