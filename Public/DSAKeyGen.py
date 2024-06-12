"""
生成 DSA 密钥文件，用于可信第三方证书生成

由于使用了 OpenSSL 的参数生成方法，会额外产生一个包含 dsa 参数 p q g 的文件 .pem
"""

import json
import os

from MyPackage import MyDSA


def main():
	url = '.'
	if not os.path.exists(url):
		print("ERROR in DSA Key Gen.")
		return
	url = url + '/dsa_key.json'

	p, q, g, x, y = MyDSA.DSA_init(512, 160)
	# print("参数p=\n{0}\n参数q=\n{1}\n参数g=\n{2}\n公钥y=\n{3}\n私钥x=\n{4}".format(p, q, g, y, x))

	data = {'p': p, 'q': q, 'g': g, 'x': x, 'y': y}
	with open(url, 'w') as f:
		# 使用 json.dump() 函数将数据写入文件
		json.dump(data, f, indent=4, ensure_ascii=False)


if __name__ == '__main__':
	main()


