import json
import os
import time

from Crypto import Random

from MyPackage import MyDSA


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

	def __init__(self, src_id, dst_id):
		"""chat_type={'send'|'receive'}"""
		self.src_id = src_id
		self.dst_id = dst_id

		self.sndFile = urlGen(src_id, dst_id)
		self.recFile = urlGen(dst_id, src_id)

		self._count = 0  # 消息 id 计数器
		self.sessionKey = None
		self.dst_pubKey = None  # 对方公钥
		self.src_priKey = None  # 自己私钥


	@staticmethod
	def endSYN(url, mid, msg):
		"""发送结束标识，包含结束原因"""
		jsonData = {
			'id': mid,
			'type': MyChat._END,
			'msg': msg
		}
		with open(url, 'r') as f:
			newData = json.load(f).append(jsonData)

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
			return
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
				MyChat.endSYN(self.sndFile, self._count, "对方启动失败: 没找到证书")
				return
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
			MyChat.endSYN(self.sndFile, self._count, "对方启动失败: 证书验证错误")
			return

		with open('./rsa_key.json', 'r') as f:  # 提取自己的私钥
			data = json.load(f)
			self.src_priKey = (data['n'], data['d'])

		print("***证书验证成功***\n")

		# ************************************************* #

		# 等待 AES 密钥生成和保存
		print("***正在生成会话密钥***")
		self.sessionKey = Random.get_random_bytes(MyChat._AES_KEY_LEN)
		print("***会话密钥生成成功***")
		print("***模块启动完毕，可以开始聊天***")

	def sendOneMsg(self):
		pass
