import os
from collections import defaultdict

# 定义根目录路径和目标文件夹
# 多个反汇编的指令合并到一起
root_folder = 'D:\complexdata\instrusctiondata\\test\instructions'
output_folder = os.path.join(root_folder, 'merged_files')

# 确保目标文件夹存在，如果不存在则创建
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# 创建一个字典，用于存储相同文件名前缀的文件内容
file_groups = defaultdict(list)

# 遍历文件夹中的所有文件
for file_name in os.listdir(root_folder):
    file_path = os.path.join(root_folder, file_name)

    # 只处理文件
    if os.path.isfile(file_path):
        # 获取下划线前的部分作为文件组名
        prefix = file_name.split('_')[0]

        # 将文件内容添加到相应的组中
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            file_groups[prefix].append(content)

# 将每个组中的文件内容合并，并写入新的文件到目标文件夹
for prefix, contents in file_groups.items():
    output_file = os.path.join(output_folder, f"{prefix}.txt")

    # 将该组所有文件内容合并写入新文件
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for content in contents:
            outfile.write(content)
            outfile.write('\n')  # 添加换行符确保文件内容之间有分隔

print("文件合并完成，结果已保存到 'merged_files' 文件夹中。")
