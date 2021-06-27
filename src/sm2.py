from gmssl import sm3, func
from ecc import *
from random import randint
from ecc_lib import *
from math import ceil, floor


def sm3_hash(message):
    """
    SM3哈希函数调用包装
    :param message: 消息,bytes
    :return: sm3哈希结果,str
    """
    return sm3.sm3_hash(func.bytes_to_list(message))


def kdf(bitz, k_len):
    """
    密钥派生函数
    :param bitz: 需要派生的字节串,bytes
    :param k_len: 比特长度,int
    :return: 密钥数据比特串k,bytes
    """
    ct = 0x00000001
    h_len = 256 // 8
    ha = []
    for i in range(ceil(k_len / h_len)):
        ct_bytes = bytes.fromhex('{:08x}'.format(ct))
        ha.append(bytes.fromhex(sm3_hash(bitz + ct_bytes)))
        ct += 1
    if k_len % h_len != 0:
        ha[-1] = ha[-1][:k_len - (h_len * floor(k_len / h_len))]
    return b''.join(habytes for habytes in ha)


def sm2_enc(mes, g, n, pub):
    """
    SM2 加密函数
    :param mes:明文消息,str
    :param g: 基点G,Point
    :param n: 阶数n,int
    :param pub: 使用的公钥,Point
    :return: SM2密钥加密结果
    """
    k_len = len(mes)
    while True:
        k = randint(1, n - 1)
        #k = 0x384f30353073aeece7a1654330a96204d37982a3e15b2cb5
        c_1 = bytes(g * k)
        if pub.is_zero():  # 对于sm2推荐曲线，h等于1
            raise ValueError("This point cannot be used as public key")
        s = pub * k
        x_bytes = align(s.x)
        y_bytes = align(s.y)
        t = kdf(x_bytes + y_bytes, k_len)
        if t != b'\x00' * k_len:
            break
    c_2 = bytes_xor(mes.encode(), t, k_len)
    c_3 = bytes.fromhex(sm3_hash(x_bytes + mes.encode() + y_bytes))
    return c_1 + c_3 + c_2


def sm2_dec(cipher, g, pri):
    """
    SM2解密方法
    :param cipher:密文,bytes
    :param g: 基点G,Point
    :param pri: 私钥,int
    :return: SM2解密结果,bytes
    """
    length = ceil(math.log(g.p, 2) / 8) + 1
    c_1_byte = cipher[:length]
    c_1 = from_bytes(c_1_byte, g.p, g.a, g.b)
    if c_1.is_zero():
        raise ValueError("This C1 is wrong. Check the cipher")
    tmp = c_1 * pri
    x_bytes = align(tmp.x)
    y_bytes = align(tmp.y)
    k_len = len(cipher) - length - 32
    t = kdf(x_bytes + y_bytes, k_len)
    if t == b'\x00' * k_len:
        raise ValueError("This t is wrong. ")
    c_2 = cipher[-k_len:]
    m = bytes_xor(c_2, t, k_len)
    u = bytes.fromhex(sm3_hash(x_bytes + m + y_bytes))
    c_3 = cipher[length:length + 32]
    if u != c_3:
        raise ValueError("Hash is wrong.")
    return m


def main():
    g = Point(0x4ad5f7048de709ad51236de65e4d4b482c836dc6e4106640, 0x02bb3a02d4aaadacae24817a4ca3a1b014b5270432db27d2,
              0xbdb6f4fe3e8b1d9e0da8c0d46f4c318cefe4afe3b6b8551f, 0xbb8e5e8fbc115e139fe6a814fe48aaa6f0ada1aa5df91985,
              0x1854bebdc31b21b7aefc80ab0ecd10d5b1b3308e6dbf11c1)
    n = 0xbdb6f4fe3e8b1d9e0da8c0d40fc962195dfae76f56564677
    mes = 'encryption standard'
    pub = Point(0x79f0a9547ac6d100531508b30d30a56536bcfc8149f4af4a, 0xae38f2d8890838df9c19935a65a8bcc8994bc7924672f912,
                0xbdb6f4fe3e8b1d9e0da8c0d46f4c318cefe4afe3b6b8551f, 0xbb8e5e8fbc115e139fe6a814fe48aaa6f0ada1aa5df91985,
                0x1854bebdc31b21b7aefc80ab0ecd10d5b1b3308e6dbf11c1)
    pri = 0x58892b807074f53fbf67288a1dfaa1ac313455fe60355afd
    cipher = sm2_enc(mes, g, n, pub)
    print(sm2_dec(cipher, g, pri))


if __name__ == "__main__":
    main()
