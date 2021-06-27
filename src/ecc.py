from ecc_lib import *
import copy
import math


class Point:
    def __init__(self, x, y, p, a, b):
        """
        Point constructor.
        :param x: x,int
        :param y: y,int
        :param p: 素数p,int
        :param a: 参数a,int
        :param b: 参数b,int
        """
        self.x = x
        self.y = y
        self.p = p
        self.a = a
        self.b = b

    def is_zero(self):
        """
        检查该点是否为无穷远点
        :return: 是无穷远点(0,0)/否，bool
        """
        return self.x == 0 and self.y == 0

    def check(self, other):
        """
        参数检查，用于检验是否为同一曲线
        :param other: 另一个点,Point
        :return: 是同一曲线/否，bool
        """
        if isinstance(other, Point) and self.p == other.p and self.a == other.a and self.b == other.b:
            return True
        else:
            return False

    def __add__(self, other):
        """
        ECC加法
        :param other: 另一个点,Point
        :return: 加法结果，Point
        """
        if not self.check(other):
            raise IndexError("You get wrong args.")
        if self.is_zero():
            return copy.deepcopy(other)
        elif other.is_zero():
            return copy.deepcopy(self)
        elif self == other:
            lam = (3 * (self.x ** 2) + self.a) * get_inv((2 * self.y) % self.p, self.p) % self.p
            x = (lam ** 2 - 2 * self.x) % self.p
            y = (lam * (self.x - x) - self.y) % self.p
            return Point(x, y, self.p, self.a, self.b)
        elif self.x == other.x:
            return Point(0, 0, self.p, self.a, self.b)
        else:
            lam = (other.y - self.y) * get_inv((other.x - self.x) % self.p, self.p) % self.p
            x = (lam ** 2 - other.x - self.x) % self.p
            y = (lam * (self.x - x) - self.y) % self.p
            return Point(x, y, self.p, self.a, self.b)

    def __neg__(self):
        """
        点的逆元方法
        :return: 该点的逆元,Point
        """
        return Point(self.x, (-self.y) % self.p, self.p, self.a, self.b)

    def __eq__(self, other):
        """
        检查两个点是否相等
        :param other: 另一个点，Point
        :return: 是一个点/否，bool
        """
        if self.check(other):
            return self.x == other.x and self.y == other.y
        else:
            return self.check(other)

    def __sub__(self, other):
        """
        ECC减法
        :param other: 另一个点，Point
        :return: 减法结果，Point
        """
        return self + (-other)

    def __mul__(self, times):
        """
        ECC乘法，请将倍乘数后置
        :param times: 倍乘数,int
        :return: 乘法结果，Point
        """
        result = Point(0, 0, self.p, self.a, self.b)
        times_bin = bin(times)[2:]
        for i in range(len(times_bin)):
            result += result
            if times_bin[i] == '1':
                result += self
        return result

    def __bytes__(self):
        """
        消息编码，通过bytes(x)调用
        :return: 消息编码结果，bytes
        """
        if self.is_zero():
            return "00"
        else:
            y = self.y & 0b1
            if y == 0:
                pc = "02"
            else:
                pc = "03"
            length = math.ceil(math.log(self.p, 2)/8) * 2
            x = '{:0{}X}'.format(self.x, length)
            return bytes.fromhex(pc + x)


def from_bytes(byte, p, a, b):
    """
    消息编码复原
    :param byte: 需要编码的消息，bytes
    :param p:素数p,int
    :param a:参数a,int
    :param b:参数b,int
    :return:构建的点,Point
    """
    y_bit = 0
    y = 0
    if byte[0] == 0:
        return Point(0, 0, p, a, b)
    elif byte[0] != 2 and byte[0] != 3:
        raise IndexError("wrong args!")
    elif byte[0] == 2:
        y_bit = 0
    elif byte[0] == 3:
        y_bit = 1
    x = int(byte[1:].hex(), 16)
    alpha = (x ** 3 + a * x + b) % p
    beta = sqrt(alpha, p)
    if (beta & 0b1) == y_bit:
        y = beta
    else:
        y = p - beta
    return Point(x, y, p, a, b)


def diffie_hellman(g, n_a, n_b):
    """
    Diffie-Hellman密钥交换
    :param g: 基点G, Point
    :param n_a: A私钥n_a,int
    :param n_b: B私钥n_b,int
    :return: void
    """
    p_a = g * n_a
    p_b = g * n_b
    print("public key a, x:" + str(p_a.x) + " public key a, y:" + str(p_a.y))
    print("public key b, x:" + str(p_b.x) + " public key b, y:" + str(p_b.y))
    k_a = p_b * n_a
    k_b = p_a * n_b
    print(k_a == k_b)


def ecc_enc(g, k, p_m, p_b):
    """
    ecc加密方法
    :param g: 基点G, Point
    :param k: 随机数k, int
    :param p_m: 消息点p_m,Point
    :param p_b: 公钥点p_b,Point
    :return: 加密列表c_m, list[Point]
    """
    c_m = [g * k, p_m + p_b * k]
    return c_m


def ecc_dec(n_b, c_m):
    """
    ecc解密方法
    :param n_b: 私钥n_b,int
    :param c_m: 消息列表c_m,list[Point]
    :return: 解密结果，Point
    """
    return c_m[1] - c_m[0] * n_b


def main():
    print("------------四则运算检验开始------------")
    p = Point(5, 1, 17, 2, 2)
    print("p.x: ", p.x, " p.y: ", p.y)
    for i in range(19):
        x = p * i
        print(str(i) + "P.x: ", x.x, " " + str(i) + "P.y: ", x.y)
    print("------------四则运算检验结束------------")
    print("------------DH交换开始------------")
    g = Point(2, 2, 211, 0, -4)
    n_a = 121
    n_b = 203
    diffie_hellman(g, n_a, n_b)
    print("------------DH交换结束------------")
    print("------------消息编码自验证开始------------")
    g = Point(2, 2, 257, 0, -4)
    b = bytes(g)
    a = from_bytes(b, 257, 0, -4)
    print(g == a)
    print("------------消息编码自验证结束------------")
    print("------------加解密自验证开始------------")
    n_b = 101
    p_b = g * n_b
    print("pb.x: ", p_b.x, " pb.y: ", p_b.y)
    k = 41
    p_m = Point(112, 26, 257, 0, -4)
    c_m = ecc_enc(g, k, p_m, p_b)
    print("c1.x: ", c_m[0].x, " c1.y: ", c_m[0].y)
    print("c2.x: ", c_m[1].x, " c2.y: ", c_m[1].y)
    mes = ecc_dec(n_b, c_m)
    print("mes.x: ", mes.x, " mes.y: ", mes.y)
    a = Point(5, 1, 17, 2, 2)
    b = a * 18
    print("b.x: ", b.x, " b.y: ", b.y)
    print("------------加解密自验证结束------------")


if __name__ == '__main__':
    main()
