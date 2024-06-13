import base64
import json
import os
import threading
import time

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

from MyPackage import MyDSA, MyRSA


def urlGen(src, dst):
	return '../Public/' + src + '_to_' + dst + '.json'


def find_by_id(data: list[dict], id_to_find: int):
	"""找到指定id的json对象"""
	for item in data:
		if isinstance(item, dict) and 'id' in item and item['id'] == id_to_find:
			return item
	return None  # 如果没有找到，返回None


class MyChat:
	"""
	负责通信的模块
	"""
	_CERT = 'CERT'
	_MSG = 'MSG'
	_END = 'END'

	_AES_KEY_LEN = 16

	def __init__(self, src_id, dst_id, is_otp=False):
		"""chat_type={'send'|'receive'}"""
		self.src_id = src_id
		self.dst_id = dst_id
		self.isOTP = is_otp  # 是否一次一密

		self.sndFile = urlGen(src_id, dst_id)
		self.recFile = urlGen(dst_id, src_id)

		self._s_count = 0  # 发送消息 id 计数器
		self._r_count = 0  # 接收消息 id 计数器
		self.sessionKey = None  # bytes 形式会话密钥
		self.dst_pubKey = None  # 对方公钥
		self.src_priKey = None  # 自己私钥

		self._session_end = False  # 进程退出标志


	@staticmethod
	def _endSYN(url, mid, msg):
		"""发送结束标识，包含结束原因"""
		jsonData = {
			'id': mid,
			'type': MyChat._END,
			'msg': msg
		}
		with open(url, 'r') as f:
			newData = json.load(f)
			newData.append(jsonData)

		with open(url, 'w') as f:
			json.dump(newData, f, indent=4)


	def chatStart(self):
		"""
		通信模块启动
		"""
		# 等待聊天文件生成
		print("***正在建立连接***")
		# 生成发送文件
		# bind(self.src_id, self.dst_id)
		with open(self.sndFile, 'w') as f:
			json.dump(f"This is the beginning of the msg from {self.src_id} to {self.dst_id}.", f)

		# 等待对方生成
		recFile = urlGen(self.dst_id, self.src_id)
		for i in range(5):
			time.sleep(2)  # 共等待 10s
			if os.path.exists(rf'{recFile}'):
				break
		else:
			print("启动失败: 没找到接收文件")
			return False
		print("***连接建立成功***\n")

		# ************************************************* #

		# 等待证书签名验证和公钥保存
		print("***正在互相验证证书***")
		# 发送证书
		jsonData = {
			'id': -1,
			'type': MyChat._CERT,
			'cert': '../Public/' + self.src_id + '_certF.json'
		}
		with open(self.sndFile, 'r') as f:
			newData = [json.load(f), jsonData]  # 此时只有一个初始json对象，转化为list

		with open(self.sndFile, 'w') as f:
			json.dump(newData, f, indent=4)
		print("你的证书已发送...sleep(5)")
		time.sleep(5)  # 等待证书的传递

		# 验证证书 保存双方 RSA 密钥
		with open(self.recFile, 'r') as f:
			data = json.load(f)
			item = find_by_id(data, -1)
			if item is None:
				print("启动失败: 没找到证书")
				MyChat._endSYN(self.sndFile, self._s_count, "对方启动失败: 没找到证书")
				return False
			else:
				print("找到对方证书...验证中...")
				certURL = item['cert']

		with open(certURL, 'r') as f:  # 证书文件
			data = json.load(f)
			cert = (self.dst_id + '|' + data['key']['n'] + data['key']['e'], (data['r'], data['s']))
			self.dst_pubKey = (data['key']['n'], data['key']['e'])  # 保存对方公钥

		with open('../Public/dsa_key.json', 'r') as f:  # dsa 密钥文件
			data = json.load(f)
			caKey = (data['g'], data['p'], data['q'], data['y'])

		if not MyDSA.verify(caKey, *cert):
			print("启动失败: 证书验证错误")
			MyChat._endSYN(self.sndFile, self._s_count, "对方启动失败: 证书验证错误")
			return False

		with open('./rsa_key.json', 'r') as f:  # 提取自己的私钥
			data = json.load(f)
			self.src_priKey = (int(data['n'], 16), int(data['d'], 16))

		print("***证书验证成功***\n")

		# ************************************************* #

		# 等待 AES 密钥生成和保存
		print("***正在生成会话密钥***")
		self.sessionKey = Random.get_random_bytes(MyChat._AES_KEY_LEN)
		print("***会话密钥生成成功***")
		print("***模块启动完毕，可以开始聊天***")
		return True

	def _sendMsg(self):
		"""发送消息的方法"""
		while True:
			# print("check01")
			msg = input(self.src_id + ':\n')  # 输入消息
			if msg == 'END':
				self._endSYN(self.sndFile, self._s_count, '对方正常退出')
				self._session_end = True
				return
			else:
				if self.isOTP:  # 一次一密要重新生成密钥
					self.sessionKey = Random.get_random_bytes(MyChat._AES_KEY_LEN)

				paddedMsg = pad(msg.encode('utf-8'), AES.block_size)
				aes = AES.new(self.sessionKey, AES.MODE_ECB)
				cipher = base64.b64encode(aes.encrypt(paddedMsg)).decode('utf-8')  # 无规律字节

				rsaKey = (int(self.dst_pubKey[0], 16), int(self.dst_pubKey[1], 16))
				keyCipher = hex(MyRSA.RSA_Enc(rsaKey[0], rsaKey[1], self.sessionKey, 'utf-8'))  # 加密会话密钥
				# 密钥加密流程：rsa -> hex
				# 明文加密流程：utf-8 encode -> pad -> aes -> base64encode -> utf-8 decode
				jsonData = {
					'id': self._s_count,
					'type': self._MSG,
					'key': keyCipher,
					'msg': cipher
				}

				with open(self.sndFile, 'r') as f:
					newData = json.load(f)
					newData.append(jsonData)
					# print(f'check newData: {newData}')

				with open(self.sndFile, 'w') as f:
					json.dump(newData, f, indent=4)

				self._s_count = self._s_count + 1


	def _receiveMsg(self):
		"""接收消息的方法"""
		while True:
			# print("check02")
			with open(self.recFile, 'r') as f:
				data = json.load(f)
				newData = find_by_id(data, self._r_count)
				if newData is None:  # 没有新消息
					time.sleep(5)
					continue

			if newData['type'] == self._END:  # 对方结束
				print(newData['msg'])
				self._session_end = True
				return

			newKey = MyRSA.RSA_Dec(*self.src_priKey, int(newData['key'], 16)).to_bytes(self._AES_KEY_LEN, 'little')  # 解出 aes 密钥
			aes = AES.new(newKey, AES.MODE_ECB)

			# 密文解密流程：base64decode -> aes -> unpad -> utf-8 decode
			newCipher = base64.b64decode(newData['msg'])  # bytes 密文
			paddedMsg = aes.decrypt(newCipher)
			newMsg = unpad(paddedMsg, AES.block_size).decode('utf-8')
			print("---------------------------------")  # 分隔线
			print(f"{self.dst_id}:\n{newMsg}")
			self._r_count = self._r_count + 1


	def msgStart(self):
		"""
		启动消息收发线程
		"""
		receive_thread = threading.Thread(target=self._receiveMsg)
		send_thread = threading.Thread(target=self._sendMsg)

		# 守护线程
		receive_thread.daemon = True
		send_thread.daemon = True
		# print("check0")
		receive_thread.start()
		send_thread.start()

		# print("check1")

		# 主线程等待
		try:
			while not self._session_end:
				time.sleep(1)
		except KeyboardInterrupt:
			pass

		print("***主线程结束***")
