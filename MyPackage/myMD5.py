"""
MD5 消息摘要算法
数据采用小端序处理
"""

class MyMD5:

	@staticmethod
	def MD5(msg: str):
		"""
		对消息进行MD5哈希运算
		"""
		byteMsg = MD5_Padding(msg)
		# print("byteMsg: {0}".format(byteMsg))

		blockNum = len(byteMsg) // 64  # 64B 一组
		blocks = []
		for i in range(blockNum):
			blocks.append(byteMsg[i * 64:i * 64 + 64])
		# print("blocks: {0}".format(blocks))

		link = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]  # 初始链接变量
		for block in blocks:
			link = accLoop(link, block)
		# print("link: {0}".format(link))

		dgst = bytes()
		for num in link:
			dgst = dgst + num.to_bytes(4, 'little')

		# print("结果为:\n{0}".format(dgst.hex()))
		return dgst.hex()

def MD5_Padding(msg: str):
	"""
	MD5 初始填充
	:param msg: 初始消息，str类型
	:return: 填充后消息，byte类型，UTF-8编码
	"""
	byteMsg = msg.encode('utf-8')

	currentLen = len(byteMsg)  # 消息字节数
	targetLen = ((currentLen - 56) // 64 + 1) * 64 + 56  # 目标字节数
	paddingLen = targetLen - currentLen
	# print("origin: {0}, target: {1}".format(currentLen, targetLen))

	padding = b'\x80'
	for i in range(paddingLen - 1):
		padding = padding + b'\x00'

	padding = padding + ((currentLen * 8) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')  # 单位为 bits
	# print("最终填充为 {0}".format(padding))
	return byteMsg + padding

def ROL(s: bytes, x: int):
	"""
	s 循环左移 x 位。
	python 的整型没有位数限制，故需要特别实现
	"""
	x = x % 32
	num = int.from_bytes(s, 'little')
	# print(hex(num), hex(num >> 32-x))
	num = (num << x) & 0xFFFFFFFF | num >> (32 - x)
	# print(hex(num))

	return num.to_bytes(4, 'little')


# 四个非线性函数

def _F(x: int, y: int, z: int):
	return (x & y) | ((~x) & z)


def _G(x: int, y: int, z: int):
	return (x & z) | (y & (~z))


def _H(x: int, y: int, z: int):
	return x ^ y ^ z


def _I(x: int, y: int, z: int):
	return y ^ (x | (~z))


def accLoop(link: list[int], block: bytes):
	"""
	单组处理
	:param link: 链接变量
	:param block: 要附加的消息分组
	:return: 新的链接变量
	"""
	rolArray = [
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	]  # 64 个移位数

	ti = [
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	]  # 64 个常量 ti，正弦计算得到

	seg = []  # 分组的分段，16*4B
	for i in range(16):
		seg.append(int.from_bytes(block[i * 4:i * 4 + 4], 'little'))
	# print("seg: {0}".format(seg))

	a, b, c, d = link[0], link[1], link[2], link[3]
	aTmp, bTmp, cTmp, dTmp = a, b, c, d

	for i in range(64):  # 64 轮处理
		if i < 16:
			val = _F(b, c, d)
			mIndex = i % 16
		elif i < 32:
			val = _G(b, c, d)
			mIndex = (5 * i + 1) % 16
		elif i < 48:
			val = _H(b, c, d)
			mIndex = (3 * i + 5) % 16
		else:
			val = _I(b, c, d)
			mIndex = (7 * i) % 16

		val = (val + a + ti[i] + seg[mIndex]) & 0xFFFFFFFF

		# 4个变量右移
		tmp = d
		d = c
		c = b
		b = b + int.from_bytes(ROL(val.to_bytes(4, 'little'), rolArray[i]), 'little')
		a = tmp

	aTmp = (a + aTmp) & 0xFFFFFFFF
	bTmp = (b + bTmp) & 0xFFFFFFFF
	cTmp = (c + cTmp) & 0xFFFFFFFF
	dTmp = (d + dTmp) & 0xFFFFFFFF

	return [aTmp, bTmp, cTmp, dTmp]


def main():
	msg = input("请输入你的消息:\n")
	MyMD5.MD5(msg)


if __name__ == "__main__":
	main()
	# MD5_Padding("helloworld")
	# print(ROL(b'\x10\x20\x30\xa0', 8).hex())
