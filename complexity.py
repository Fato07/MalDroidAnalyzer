import gc
import math
import multiprocessing
import os
import time
import hashlib
import pandas as pd
import logging
from androguard.misc import AnalyzeAPK
import csv
import tqdm

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

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


def calculate_hash(apk_path, hash_type="sha256"):
    """Calculate the hash of the APK file using md5, sha1, or sha256."""
    hash_funcs = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
    h = hash_funcs.get(hash_type)()
    if h is None:
        raise ValueError("Unsupported hash type specified.")

    with open(apk_path, "rb") as file:
        for byte_block in iter(lambda: file.read(4096), b""):
            h.update(byte_block)
    return h.hexdigest()


def entropy(s):
    """Calculate the Shannon entropy of a given string."""
    prob = {char: float(s.count(char)) / len(s) for char in dict.fromkeys(list(s))}
    return -sum(prob[char] * math.log(prob[char], 2) for char in prob)


def is_string_obfuscated(string):
    """Determine if a string is likely to be obfuscated based on its entropy."""
    return len(string) > 20 and entropy(string) > 4.5


def extract_obfuscation_features(dexes):
    """Extract obfuscation-related features from the DEX bytecode."""
    return sum(
        1
        for dex in dexes
        for string in dex.get_strings()
        if is_string_obfuscated(string)
    )


def extract_dynamic_code_features(dexes):
    """Detect dynamic code execution features in the APK."""
    return sum(
        1
        for dex in dexes
        for method in dex.get_methods()
        if "Ldalvik/system/DexClassLoader;" in str(method.get_class_name())
        or "Ldalvik/system/PathClassLoader;" in str(method.get_class_name())
    )


def calculate_apk_entropy(dexes):
    """Calculate the average entropy of all strings in the APK's DEX files."""
    total_entropy = sum(
        entropy(string) for dex in dexes for string in dex.get_strings()
    )
    string_count = sum(1 for dex in dexes for _ in dex.get_strings())
    return total_entropy / max(string_count, 1)


def calculate_code_length(dexes):
    """Calculate the total length of code in all DEX files."""
    total_length = sum(
        len(list(method.get_code().get_bc().get_instructions()))
        for dex in dexes
        for method in dex.get_methods()
        if method.get_code()
    )
    return total_length


def extract_features(apk_path):
    try:
        a, dexes, dx = AnalyzeAPK(apk_path)
        features = {
            "permissions": a.get_permissions(),
            "permissions_count": len(a.get_permissions()),
            "native_code": a.get_libraries(),
            "native_code_count": len(a.get_libraries()),
            "obfuscated_strings_count": extract_obfuscation_features(dexes),
            "dynamic_code_use_count": extract_dynamic_code_features(dexes),
            "apk_entropy": calculate_apk_entropy(dexes),
            "code_length": calculate_code_length(dexes),
            "file_size_mb": os.path.getsize(apk_path) / (1024 * 1024),  # Convert to MB
            "file_hash": calculate_hash(apk_path, "sha256"),
        }

        # Clean up memory before returning the features
        del a, dexes, dx
        gc.collect()
        return features
    except Exception as e:
        logging.error(f"Failed to process {apk_path}: {e}")
        return None


def calculate_complexity_score(features):
    """Calculate the complexity score using normalized features and assigned weights."""
    if features is None:
        return 0
    normalized_features = {}
    for feature in max_values:
        value = features.get(feature, 0)
        normalized_features[feature] = min(float(value) / max_values[feature], 1)
    return sum(
        normalized_features[feature] * weights[feature]
        for feature in normalized_features
    )


def process_apk_file(apk_path):
    label = "malware" if "malware" in apk_path.lower() else "benign"
    features = extract_features(apk_path)
    if features:
        complexity_score = calculate_complexity_score(features)
        # Flatten features
        for key, value in features.items():
            if isinstance(value, list):
                features[key] = ";".join(
                    value
                )  # Convert lists to semicolon-separated strings
        result = {
            "apk_path": apk_path,
            "label": label,
            "complexity_score": complexity_score,
            **features,
        }
        logging.info(f"Processed {apk_path}: {complexity_score}")
        return result
    else:
        logging.error(f"Skipping {apk_path} due to extraction errors.")
        return None


def process_apk_files_parallel(
    base_path, num_processes=4, output_file="analysis_results_03.csv"
):
    # Check if output file exists and read processed APKs
    if os.path.exists(output_file):
        existing_results = pd.read_csv(output_file)
        processed_apks = set(existing_results["apk_path"].tolist())
    else:
        processed_apks = set()

    # Get list of APK files
    apk_files = [
        os.path.join(root, file)
        for root, _, files in os.walk(base_path)
        for file in files
        if file.endswith(".apk") and os.path.join(root, file) not in processed_apks
    ]

    # Open output file in append mode
    with open(output_file, "a", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "apk_path",
            "label",
            "complexity_score",
            "permissions",
            "permissions_count",
            "native_code",
            "native_code_count",
            "obfuscated_strings_count",
            "dynamic_code_use_count",
            "apk_entropy",
            "code_length",
            "file_size_mb",
            "file_hash",
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # If file is empty, write header
        if os.path.getsize(output_file) == 0:
            writer.writeheader()

        with multiprocessing.Pool(processes=num_processes) as pool:
            for result in tqdm.tqdm(
                pool.imap_unordered(process_apk_file, apk_files),
                total=len(apk_files),
                desc="Processing APK files",
            ):
                if result:
                    writer.writerow(result)
                    csvfile.flush()  # Ensure data is written to disk


def main():
    base_path = "./KronoDroid_Real_Malware_03"
    output_file = "analysis_results_03.csv"

    # Process APK files with progress bar
    process_apk_files_parallel(base_path, num_processes=4, output_file=output_file)

    logging.info("Analysis completed.")


if __name__ == "__main__":
    main()
