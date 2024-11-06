import os
import pandas as pd

# 定义根目录路径和输出文件名
root_folder = os.getcwd()  # 当前目录
output_file_1 = 'excel_1.xlsx'
output_file_2 = 'excel_2.xlsx'

# 存储结果的列表
results_less_than_3000 = []
results_more_than_3000 = []

# 遍历当前目录下的所有 .txt 文件
for file_name in os.listdir(root_folder):
    if file_name.endswith('.txt'):
        file_path = os.path.join(root_folder, file_name)
        if os.path.isfile(file_path):
            try:
                # 计算文件行数
                with open(file_path, 'r', encoding='utf-8') as file:
                    line_count = sum(1 for _ in file)

                # 根据行数将结果分配到不同的列表
                if line_count < 3000:
                    results_less_than_3000.append([file_name, line_count])
                else:
                    results_more_than_3000.append([file_name, line_count])

            except Exception as e:
                print(f'无法访问文件 {file_path}: {e}')

# 创建 DataFrame 并保存为 Excel 文件
df_less_than_3000 = pd.DataFrame(results_less_than_3000, columns=['文件名', '指令数'])
df_more_than_3000 = pd.DataFrame(results_more_than_3000, columns=['文件名', '指令数'])

df_less_than_3000.to_excel(output_file_1, index=False)
df_more_than_3000.to_excel(output_file_2, index=False)

print(f'结果已保存为 {output_file_1} 和 {output_file_2}')
