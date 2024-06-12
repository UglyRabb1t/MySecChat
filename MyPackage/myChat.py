import json
import os
import time


def urlGen(src, dst):
	return '../Public/' + src + '_to_' + dst + '.json'


class MyChat:
	"""
	负责通信的模块
	"""
	CERT = 'CERT'
	MSG = 'MSG'
	END = 'END'

	def __init__(self, src_id, dst_id):
		"""chat_type={'send'|'receive'}"""
		self.src_id = src_id
		self.dst_id = dst_id

		self.sndFile = urlGen(src_id, dst_id)
		self.recFile = urlGen(dst_id, src_id)

		self.sessionKey = None
		self.dst_pubKey = None  # 对方公钥
		self.src_priKey = None  # 自己私钥

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

		# 等待证书签名验证和公钥保存
		print("***正在验证证书***")
		# 发送证书
		jsonData = {
			'type': MyChat.CERT,
			'cert': '../Public' + self.src_id + '_certF.json'
		}

		# 验证证书

		print("***证书验证成功***\n")

		# 等待 AES 密钥生成和保存
		print("***正在生成会话密钥***")

		print("***会话密钥生成成功***\n")


	def sendOneMsg(self):
		pass
