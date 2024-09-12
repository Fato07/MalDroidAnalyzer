import math
import os
import time
import hashlib
import pandas as pd
import logging
from androguard.misc import AnalyzeAPK

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the maximum expected values for each feature
max_values = {
    "permissions_count": 30,
    "native_code_count": 10,
    "obfuscated_strings_count": 50,
    "dynamic_code_use_count": 20,
    "apk_entropy": 8,
    "code_length": 10000,
    "file_size_mb": 100,
}

# Define the weights for each feature
weights = {
    "permissions_count": 1.0,
    "native_code_count": 1.5,
    "obfuscated_strings_count": 2.0,
    "dynamic_code_use_count": 2.5,
    "apk_entropy": 3.0,
    "code_length": 1.0,
    "file_size_mb": 0.5,
}

def calculate_hash(apk_path, hash_type='sha256'):
    """ Calculate the hash of the APK file using md5, sha1, or sha256. """
    hash_funcs = {'md5': hashlib.md5, 'sha1': hashlib.sha1, 'sha256': hashlib.sha256}
    h = hash_funcs.get(hash_type)()
    if h is None:
        raise ValueError("Unsupported hash type specified.")

    with open(apk_path, 'rb') as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            h.update(byte_block)
    return h.hexdigest()

def entropy(s):
    """ Calculate the Shannon entropy of a given string. """
    prob = {char: float(s.count(char)) / len(s) for char in dict.fromkeys(list(s))}
    return -sum(prob[char] * math.log(prob[char], 2) for char in prob)

def is_string_obfuscated(string):
    """ Determine if a string is likely to be obfuscated based on its entropy. """
    return len(string) > 20 and entropy(string) > 4.5

def extract_obfuscation_features(dexes):
    """ Extract obfuscation-related features from the DEX bytecode. """
    return sum(1 for dex in dexes for string in dex.get_strings() if is_string_obfuscated(string))

def extract_dynamic_code_features(dexes):
    """ Detect dynamic code execution features in the APK. """
    return sum(1 for dex in dexes for method in dex.get_methods() if 'Ldalvik/system/DexClassLoader;' in str(method.get_class_name()) or 'Ldalvik/system/PathClassLoader;' in str(method.get_class_name()))

def calculate_apk_entropy(dexes):
    """ Calculate the average entropy of all strings in the APK's DEX files. """
    total_entropy = sum(entropy(string) for dex in dexes for string in dex.get_strings())
    string_count = sum(1 for dex in dexes for _ in dex.get_strings())
    return total_entropy / max(string_count, 1)

def calculate_code_length(dexes):
    """ Calculate the total length of code in all DEX files. """
    total_length = sum(len(list(method.get_code().get_bc().get_instructions())) for dex in dexes for method in dex.get_methods() if method.get_code())
    return total_length

def extract_features(apk_path):
    """ Extract features from the APK file, including permissions and other complexity indicators. """
    try:
        a, dexes, dx = AnalyzeAPK(apk_path)
        permissions = a.get_permissions()
        permissions_count = len(permissions) 
        native_code = a.get_libraries()
        obfuscated_strings_count = extract_obfuscation_features(dexes)
        dynamic_code_use = extract_dynamic_code_features(dexes)
        apk_entropy = calculate_apk_entropy(dexes)
        code_length = calculate_code_length(dexes)
        file_size_bytes = os.path.getsize(apk_path)
        file_hash = calculate_hash(apk_path, 'sha256')
        return {
            "permissions": permissions,
            "permissions_count": permissions_count,
            "native_code": native_code,
            "obfuscated_strings_count": obfuscated_strings_count,
            "dynamic_code_use_count": dynamic_code_use,
            "apk_entropy": apk_entropy,
            "code_length": code_length,
            "file_size": file_size_bytes / (1024 * 1024),  # Convert to MB
            "file_hash": file_hash,
        }
    except Exception as e:
        logging.error(f"Failed to process {apk_path}: {e}")
        return None

def calculate_complexity_score(features):
    """ Calculate the complexity score using normalized features and assigned weights. """
    if features is None:
        return None
    normalized_features = {feature: min(float(features[feature]) / max_values[feature], 1) for feature in features if feature in max_values}
    return sum(normalized_features[feature] * weights[feature] for feature in normalized_features)

def process_apk_files(base_path):
    """ Process each APK file in the given directory for feature extraction and complexity scoring. """
    results = []
    for root, dirs, files in os.walk(base_path):
        label = 'malware' if 'malware' in root.lower() else 'benign'
        for file in files:
            if file.endswith(".apk"):
                apk_path = os.path.join(root, file)
                features = extract_features(apk_path)
                if features:
                    complexity_score = calculate_complexity_score(features)
                    results.append({"apk_path": apk_path, "label": label, "complexity_score": complexity_score, **features})
                    logging.info(f"Processed {apk_path}: {complexity_score}")
                else:
                    logging.error(f"Skipping {apk_path} due to extraction errors.")
    return results

def export_results(results, filename="analysis_results.csv"):
    """ Export the analysis results to a CSV file. """
    if not results:
        logging.warning("No results to export.")
        return

    import csv
    keys = results[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)
        logging.info(f"Results exported to {filename}")

def main():
    base_path = "./KronoDroid_Real_Malware_01"
    results = process_apk_files(base_path)
    export_results(results)
    logging.info("Analysis completed.")

if __name__ == "__main__":
    main()