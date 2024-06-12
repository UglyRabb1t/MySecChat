"""
DSA数字签名算法
"""
import random

from .myMD5 import MyMD5
from .myRSA import Euclid_algorithm, mod_fast_pow
from .DSAParam import DSAParam


pDIGITS = 512  # 参数 p 长度
qDIGITS = 160  # 参数 q 长度
# TIMES = 8  # 素性检验轮数


class MyDSA:

	@staticmethod
	def DSA_init(p_digit: int, q_digit: int):
		"""
		生成十六进制str密钥 (p, q, g, x, y)
		"""
		p, q, g = DSAParam(p_digit, q_digit)
		p = int(p, 16)
		q = int(q, 16)
		g = int(g, 16)
	# 	while True:
	# 		counter = 0
	# 		q = generate_large_prime(q_digit)
	# 		while True:
	# 			p = generate_large_prime(p_digit)
	# 			if (p - 1) % q == 0:  # q 是 p-1 素因数
	# 				counter = -1
	# 				break
	# 			counter = counter + 1
	# 			if counter >= 10:
	# 				break
	#
	# 		if counter == -1:
	# 			break
	#
	# 	print("p:{0}\nq:{0}".format(p, q))
	#
	# 	while True:
	# 		h = random.randint(2, p-2)
	# 		g = mod_fast_pow(h, (p-1 // q), p)
	# 		if mod_fast_pow(g, q, p) == 1:  # h 是 mod p 原根
	# 			break
	# 	print("h:{0}\ng:{0}".format(h, g))
	#
		x = random.randint(1, q-1)  # 私钥
		y = mod_fast_pow(g, x, p)  # 公钥
		# print("x:{0}\ny:{0}".format(x, y))

		return hex(p), hex(q), hex(g), hex(x), hex(y)


	@staticmethod
	def sign(sk: tuple[str, str, str, str], msg: str):
		"""
		DSA签名算法
		:param sk: 十六进制表示的私钥 (g, p ,q, x)
		:param msg: str类型消息
		:return: 十六进制str签名 (r, s)
		"""
		g, p, q, x = (int(hex_str, 16) for hex_str in sk)

		k = random.randint(1, q-1)
		r = mod_fast_pow(g, k, p) % q
		kInv = Euclid_algorithm(k, q)[0] % q
		s = (kInv * (int(MyMD5.MD5(msg), 16) + x * r)) % q  # 一开始漏了 mod q

		return hex(r), hex(s)


	@staticmethod
	def verify(pk: tuple[str, str, str, str], msg: str, sign: tuple[str, str]):
		"""
		DSA验签算法
		:param pk: 十六进制表示的公钥 (g, p ,q, y)
		:param msg: str类型消息
		:param sign: 签名对 (r, s)
		:return: Boolean
		"""
		g, p, q, y = (int(hex_str, 16) for hex_str in pk)
		r, s = (int(hex_str, 16) for hex_str in sign)

		w = Euclid_algorithm(s, q)[0] % q
		u1 = (int(MyMD5.MD5(msg), 16) * w) % q
		u2 = (r * w) % q
		v = ((mod_fast_pow(g, u1, p) * mod_fast_pow(y, u2, p)) % p) % q

		if v == r:
			return True
		else:
			return False


def main():
	p, q, g, x, y = MyDSA.DSA_init(pDIGITS, qDIGITS)

	print("p:{0}\nq:{1}\ng:{2}\nx:{3}\ny:{4}".format(p,q,g,x,y))
	sk = (g, p, q, x)
	pk = (g, p, q, y)
	msg = "Hello, world!"
	# msg = "Hello, world!!!!!HELLO"
	signature = MyDSA.sign(sk, msg)
	print(signature)
	print(MyDSA.verify(pk, msg, signature))
	# if (mod_fast_pow(int(g,16), int(q,16), int(p,16)) == 1) != (MyDSA.verify(pk, msg, signature)):
	# 	print("ERROR")


if __name__ == '__main__':
	# print(MyMD5.MD5("hello"))
	main()
