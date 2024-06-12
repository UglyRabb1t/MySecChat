"""
用 RSA 算法对明文 “math” 加解密
要求 n 达到 2048 bit
p q 1024 bit
"""

# import decimal
import random
import secrets

# D = decimal.Decimal  # 生成器
DIGITS = 1024  # 大素数位数
TIMES = 8  # 素性检验轮数


def miller_rabin_check(n: int, t: int):
	"""
	使用Miller_Rabin素性检验算法，判断n是否为素数
	:param n: 正奇数
	:param t: 轮数
	:return: bool值，判断是素数返回True，否则False
	"""
	k = 0
	m = n - 1
	while (m & 1) == 0:
		m = m >> 1
		k += 1  # 拆分为 2^k * m 形式
	for i in range(t):
		a = random.randint(1, n - 1)
		b = pow(a, m, n)
		flag = 0
		if b == 1:
			continue

		for j in range(k):  # 排除最后 -1 的情况
			if (b + 1) % n == 0:  # 出现 -1
				flag = 1
				break
			else:
				b = (b * b) % n

		if flag == 1:
			continue
		else:
			return False
	return True


def generate_large_integer(num_digits: int):
	"""
	生成指定二进制位数范围的大整数
	:param num_digits: 大整数的位数
	:return: 生成的大整数
	"""
	UPPER = (2 ** num_digits) - 1
	LOWER = 2 ** (num_digits - 1)

	# print("UPPER:\n{0}".format(UPPER))
	# print("LOWER:\n{0}".format(LOWER))

	while True:
		random_bytes = secrets.token_bytes((num_digits + 7) // 8)  # 生成num_digits位的随机字节
		random_integer = int.from_bytes(random_bytes, 'big')
		if LOWER < random_integer < UPPER:
			break

	return random_integer


def generate_large_prime(num_digits: int):
	"""
	生成指定二进制位数范围的大素数
	:param num_digits: 大素数的位数
	:return: 生成的大素数
	"""
	random_large_integer = generate_large_integer(num_digits)
	while True:
		while True:
			if random_large_integer % 2 == 1:  # 确保为奇数
				break
			else:
				random_large_integer = generate_large_integer(num_digits)

		if miller_rabin_check(random_large_integer, TIMES):  # 找到
			break
		else:
			random_large_integer = generate_large_integer(num_digits)
	return random_large_integer


def EA_update(old: int, new: int, q: int):
	"""
	进行欧几里得算法中的状态迭代
	"""
	tmp = old - new * q
	return new, tmp


def Euclid_algorithm(a: int, b: int):
	"""
	欧几里得算法
	:param a: 运算数1
	:param b: 运算数2
	:return: s: 贝祖等式s; t: 贝祖等式t; gcd: (a, b)
	"""
	s0, s1 = 1, 0
	t0, t1 = 0, 1
	flag = True  # 标记大小关系用于输出

	if a >= b:
		r0, r1 = a, b
	else:
		r0, r1 = b, a
		flag = False

	# print("{:<5} {:<10} {:<10} {:<10} {:<10}".format('j', 's_j', 't_j', 'q_j+1', 'r_j+1'))
	# print("{:<5} {:<10} {:<10} {:<10} {:<10}".format(-3, ' ', ' ', ' ', r0))
	# print("{:<5} {:<10} {:<10} {:<10} {:<10}".format(-2, s0, t0, ' ', r1))
	# count = -1

	while r1 != 0:
		q = r0 // r1

		s0, s1 = EA_update(s0, s1, q)
		t0, t1 = EA_update(t0, t1, q)
		r0, r1 = EA_update(r0, r1, q)
		# print("{:<5} {:<10} {:<10} {:<10} {:<10}".format(count, s0, t0, q, r1))
		# count += 1

	if flag:
		return s0, t0, r0
	else:
		return t0, s0, r0


def mod_fast_pow(base: int, exp: int, mod: int):
	"""
	模快速幂算法
	:param base: 底数
	:param exp: 指数
	:param mod: 模数
	"""
	ans = 1
	base = base % mod
	while exp > 0:
		if exp & 1 == 1:
			ans = (ans * base) % mod
		exp = int(exp // 2)
		base = (base * base) % mod
	return ans


class MyRSA:

	@staticmethod
	def RSA_init():
		"""
		生成密钥 (n, e, d)
		"""
		p = generate_large_prime(DIGITS)
		q = generate_large_prime(DIGITS)
		# print("p: {0}".format(p))
		# print("q: {0}".format(q))

		n = p * q
		# print("n: {0}".format(n))

		m = (p - 1) * (q - 1)
		# print("m: {0}".format(m))

		while True:
			e = random.randint(2, m - 1)
			result = Euclid_algorithm(m, e)
			if result[2] == 1:  # 互素
				break
		d = result[1] % m

		# print("pk:(\nn={0:X},\ne={1:X}\n),\nsk:(\nn={0:X},\nd={2:X}\n)".format(n, e, d))

		return n, e, d

	@staticmethod
	def RSA_Enc(n: int, e: int, msg: str, code: str):
		"""
		:param n: 模数
		:param e: 公钥
		:param msg: 消息
		:param code: 编码方式
		:return: 整型密文
		"""
		int_msg = int.from_bytes(msg.encode(code), 'little')
		cipher = mod_fast_pow(int_msg, e, n)
		return cipher

	@staticmethod
	def RSA_Dec(n: int, d: int, cipher: int, code: str):
		"""
		:param n: 模数
		:param d: 私钥
		:param cipher: 密文
		:param code: 编码方式
		:return: (utf-8 字符串明文， 整型明文)
		"""
		dec = mod_fast_pow(cipher, d, n)
		utf8dec = dec.to_bytes((dec.bit_length() + 7) // 8, 'little').decode(code)
		return utf8dec, dec

def RSA():
	n, e, d = MyRSA.RSA_init()
	msg = input("输入消息(注意长度):\n").encode('utf-8')
	int_msg = int.from_bytes(msg, 'little')
	print("Message(HEX):\n{0:X}".format(int_msg))

	cipher = mod_fast_pow(int_msg, e, n)
	print("Encryption(HEX):\n{0:X}".format(cipher))

	dec = mod_fast_pow(cipher, d, n)
	print("Decryption(HEX):\n{0:X}".format(dec))
	utf8dec = dec.to_bytes((dec.bit_length() + 7) // 8, 'little').decode('utf-8')
	print("Decryption(UTF-8):\n{0}".format(utf8dec))


if __name__ == "__main__":
	RSA()
