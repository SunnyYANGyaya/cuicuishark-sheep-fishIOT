import re
import binascii

def extract_hex_data(log_file):
    """
    从日志文件中提取十六进制数据，并在处理每组4字节数据时进行字节序反转（小端）。
    
    参数:
        log_file (str): 日志文件的路径。
    
    返回:
        str: 提取并反转字节序后的十六进制数据，拼接成完整的一个字符串。
    """
    # 定义正则表达式模式，用于匹配日志中的十六进制数据
    hex_pattern = re.compile(r":\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})")
    
    # 初始化一个列表，用于存储提取的十六进制数据
    hex_data = []

    # 打开日志文件进行读取
    with open(log_file, "r") as f:
        # 遍历文件的每一行
        for line in f:
            # 使用正则表达式在当前行中搜索匹配的十六进制数据
            match = hex_pattern.search(line)
            if match:
                # 如果找到匹配项，则提取四组十六进制数据
                for group in match.groups():
                    # 去掉每组数据中的空格（如果有）
                    hex_word = group.replace(" ", "")
                    # 将4字节数据分割成两个两个的字节，并反转顺序
                    if len(hex_word) == 8:
                        # 分割成四个两两的字节
                        bytes_list = [hex_word[i:i+2] for i in range(0, 8, 2)]
                        # 反转字节顺序
                        reversed_bytes = bytes_list[::-1]
                        # 将反转后的字节拼接为新的字符串
                        reversed_word = ''.join(reversed_bytes)
                        hex_data.append(reversed_word)
                    else:
                        # 如果数据长度不为8位，则直接添加（假设这种情况不存在）
                        hex_data.append(hex_word)

    # 将提取的并已反转字节序的数据拼接成一个完整的字符串
    return ''.join(hex_data)

def hex_to_bin(hex_data):
    """
    将十六进制字符串转换为二进制数据
    """
    bin_data = binascii.unhexlify(hex_data)
    return bin_data

def save_to_bin(bin_data, output_file):
    """
    将二进制数据保存到文件
    """
    with open(output_file, "wb") as f:
        f.write(bin_data)
    print(f"二进制数据已保存到 {output_file}")

def main():
    log_file = "AllInFlash.log"  # 日志文件路径
    output_file = "AllInFlash.bin" # 输出文件路径

    # 提取十六进制数据
    hex_data = extract_hex_data(log_file)
    if hex_data:
        # 转换为二进制数据
        bin_data = hex_to_bin(hex_data)
        # 保存到文件
        save_to_bin(bin_data, output_file)
    else:
        print("未找到有效的十六进制数据。")

if __name__ == "__main__":
    main()