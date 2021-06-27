from random import randint


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


def fast_pow(x, n, m):
    """
    快速幂实现
    :param x:底数x,int
    :param n: 指数n, int
    :param m: 模数m,int
    :return: x^n%m,int
    """
    result = 1
    while n > 0:
        if n % 2 == 1:
            result = result * x % m
        x = x * x % m
        n = n // 2
    result = result % m
    return result


def lucas(x, y, k, p):
    """
    指定lucas序列生成
    :param x: 参数X,int
    :param y: 参数Y,int
    :param k: 参数K,int
    :param p: 素数p,int
    :return: 两个lucas序列参数U,V,[int,int]
    """
    delta = x ** 2 - 4 * y
    k_bin = bin(k)[2:]
    u, v = 1, x
    inv_2 = (get_inv(2, p)) % p
    for i in range(1, len(k_bin)):
        u, v = (u * v) % p, ((v ** 2 + delta * (u ** 2)) * inv_2) % p
        if k_bin[i] == '1':
            u, v = ((x * u + v) * inv_2) % p, ((x * v + delta * u) * inv_2) % p
    return [u, v]


def sqrt(g, p):
    """
    p有限域下的开方函数
    :param g: 需要开方的参数g,int
    :param p: 素数p,int
    :return: 开方结果,int
    """
    if p % 4 == 3:
        u = p // 4
        y = fast_pow(g, u + 1, p)
        z = (y ** 2) % p
        if z == g:
            return y
        else:
            raise ValueError("Can't find the root!")
    elif p % 8 == 5:
        u = p // 8
        z = fast_pow(g, 2 * u + 1, p)
        if z % p == 1:
            return fast_pow(g, u + 1, p)
        elif z % p == p - 1:
            return (2 * g * fast_pow(4 * g, u, p)) % p
        else:
            raise ValueError("Can't find the root!")
    elif p % 8 == 1:
        u = p // 8
        while True:
            x = randint(1, p - 1)
            y = g
            u_1, v = lucas(x, y, 4 * u + 1, p)
            if v ** 2 % p == 4 * y % p:
                return (v * get_inv(2, p)) % p
            elif u_1 % p != 1 and u_1 % p != p - 1:
                raise ValueError("Can't find the root!")


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
