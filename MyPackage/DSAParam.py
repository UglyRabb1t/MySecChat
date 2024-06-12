"""
生成DSA参数 (p, q, g)
"""

import subprocess


def DSAParam(p_bits=512, q_bits=160):
    """
    获取十六进制形式的DSA参数 (p,q,g)
    """
    # 生成DSA参数
    generate_dsa_parameters(str(p_bits), str(q_bits))

    # 提取并显示DSA参数
    dsa_params = extract_dsa_parameters()
    # print(dsa_params)

    p_hex = ''
    q_hex = ''
    g_hex = ''

    # 遍历output的每一行，并检查是否包含P, Q, G的值
    lines = dsa_params.strip().split('\n')
    parsing_p = False
    parsing_q = False
    parsing_g = False

    for line in lines:
        line = line.strip()
        if line.startswith('P:'):
            parsing_p = True
            parsing_q = False
            parsing_g = False
        elif line.startswith('Q:'):
            parsing_p = False
            parsing_q = True
            parsing_g = False
        elif line.startswith('G:'):
            parsing_p = False
            parsing_q = False
            parsing_g = True
        elif parsing_p:
            p_hex += line.replace(':', '')
        elif parsing_q:
            q_hex += line.replace(':', '')
        elif parsing_g:
            g_hex += line.replace(':', '')

    return '0x' + p_hex[2:], '0x' + q_hex[2:], '0x' + g_hex  # g参数输出时是没有前导00的，巨坑！


def generate_dsa_parameters(p_bits: str, q_bits: str, out_file='dsa_params.pem'):
    """
    使用OpenSSL命令生成DSA参数
    """
    command = ['openssl', 'dsaparam', '-out', out_file, p_bits, q_bits]
    subprocess.run(command, check=True)


def extract_dsa_parameters(pem_file='dsa_params.pem'):
    """
    使用OpenSSL命令提取DSA参数（OpenSSL标准格式）
    """
    command = ['openssl', 'dsaparam', '-in', pem_file, '-text', '-noout']
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    return result.stdout
