import os
import re
import matplotlib.pyplot as plt

def is_obfuscated_method_name(method_name):
    return len(method_name) < 3 or method_name in ['a', 'b', 'c']

def is_encrypted_string(string):
    pattern = r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    return re.fullmatch(pattern, string)

def is_complex_control_flow(line):
    return line.count('if-') > 1 or line.count('goto') > 1

def analyze_smali_files(directories):
    global_obfuscation_report = {}

    for directory in directories:
        obfuscation_report = {
            'method_name_obfuscation': [],
            'string_encryption': [],
            'complex_control_flow': [],
        }

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.smali'):
                    with open(os.path.join(root, file), 'r') as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines):
                            if line.startswith('.method'):
                                method_name = line.split()[2]
                                if is_obfuscated_method_name(method_name):
                                    obfuscation_report['method_name_obfuscation'].append((file, i+1, line.strip()))
                            if is_encrypted_string(line.strip()):
                                obfuscation_report['string_encryption'].append((file, i+1, line.strip()))
                            if is_complex_control_flow(line):
                                obfuscation_report['complex_control_flow'].append((file, i+1, line.strip()))

        global_obfuscation_report[directory] = obfuscation_report

    return global_obfuscation_report

def generate_report(global_obfuscation_report):
    for directory, obfuscation_report in global_obfuscation_report.items():
        print(f"\nObfuscation Report for APK: {directory}")
        for key, findings in obfuscation_report.items():
            print(f"\n  {key.replace('_', ' ').title()} ({len(findings)} instances):")
            for file, line_number, line in findings:
                print(f"    - File: {file}, Line: {line_number}, Content: {line}")

        # Visualization
        labels = list(obfuscation_report.keys())
        counts = [len(findings) for findings in obfuscation_report.values()]
        plt.figure(figsize=(10, 6))
        plt.bar(labels, counts)
        plt.xlabel('Obfuscation Type')
        plt.ylabel('Count')
        plt.title(f'Distribution of Obfuscation Techniques in {directory}')
        plt.show()

# Example usage
directories = ['output_folder1', 'output_folder2', 'output_folder3']
global_obfuscation_report = analyze_smali_files(directories)
generate_report(global_obfuscation_report)

# Using apktool to decompile APKs (run these commands in terminal)
# apktool d sample1.apk -o output_folder1
# apktool d sample2.apk -o output_folder2
# apktool d sample3.apk -o output_folder3
