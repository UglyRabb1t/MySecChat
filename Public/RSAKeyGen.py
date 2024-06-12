"""
生成一个RSA密钥对文件
"""

import json
import os

from MyPackage import MyRSA


def main():
	uid = input("请输入你的ID: ")
	url = '../' + uid
	if not os.path.exists(rf'{url}'):
		print("ID不存在！\n其实这里只有 Alice 和 Bob :P")
		return
	url = url + '/rsa_key.json'

	n, e, d = MyRSA.RSA_init()
	# print("参数n=\n{0}\n公钥e=\n{1}\n私钥d=\n{2}".format(n, e, d))

	data = {'n': hex(n), 'e': hex(e), 'd': hex(d)}
	with open(url, 'w') as f:
		# 使用 json.dump() 函数将数据写入文件
		json.dump(data, f, indent=4, ensure_ascii=False)


if __name__ == '__main__':
	main()
