"""
生成一个 `ID|公钥` 的证书
"""

import json
import os

from MyPackage import MyDSA


def certFGen(uid: str, userkey: tuple[str, str], cakey: tuple[str, str, str, str]):
	"""
	生成 `uid|n|e` 的证书
	:param uid: 用户 id
	:param userkey: 用户公钥 n|e
	:param cakey: CA 的 DSA 签名私钥 (g, p, q, x)
	"""

	url = '.'
	if not os.path.exists(rf'{url}'):
		print("ERROR in Certification Gen.")
		return
	url = url + '/' + uid + '_certF.json'

	sign =  MyDSA.sign(cakey, uid + '|' + userkey[0] + userkey[1])
	# print("签名=\n{0}".format(sign))

	data = {
		'type': 'certification',
		'CA': '我是给这证书签名的可信第三方',
		'r': sign[0],
		's': sign[1],
		'key': {
			'n': userkey[0],
			'e': userkey[1]
			}
		}
	# 由于有非ascii存在，需要 ensure_ascii=False, 以GBK打开，才能在json中直接看
	# 不添加参数会显示为utf-8编码
	with open(url, 'w') as f:
		# 使用 json.dumps() 转换编码
		# jsonData = json.dumps(data, indent=4, ensure_ascii=False).encode('utf-8')
		# 使用 json.dump() 函数将数据写入文件
		json.dump(data, f, indent=4, ensure_ascii=False)


def main():
	# 获取用户数据
	uid = input("请输入你的ID: ")
	pubKeyURL = '../' + uid # 公钥证书位置

	if not os.path.exists(rf'{pubKeyURL}'):
		print("ID不存在！")
		return

	# n = input("请输入参数n: ")
	# e = input("请输入公钥e: ")
	# pubKey = (n, e)
	pubKeyURL = pubKeyURL + '/rsa_key.json'
	pubKey: tuple[str, str]
	# 这里为了省去操作，由程序直接读取密钥文件，并不安全
	with open(pubKeyURL, 'r') as f:
		load_dict = json.load(f)
		pubKey = (load_dict['n'], load_dict['e'])
	# print(pubKey)

	# 获取 CA 私钥
	cakeyURL = 'dsa_key.json'
	with open(cakeyURL, 'r') as f:
		load_dict = json.load(f)
		cakey = (load_dict['g'], load_dict['p'], load_dict['q'], load_dict['x'])
	# print(cakey)

	certFGen(uid, pubKey, cakey)
	print("证书生成成功！")


if __name__ == '__main__':
	main()
	# with open('Alice_certF.json', 'r') as f:
	# 	data = json.load(f)
	# 	print(data)
