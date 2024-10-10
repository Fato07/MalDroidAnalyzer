import gc
import os
import hashlib
import csv
import logging
from logging.handlers import RotatingFileHandler
from androguard.misc import AnalyzeAPK
from tqdm import tqdm
import time
import math

# ============================
# Logging Setup with Rotation
# ============================

logger = logging.getLogger("APKAnalysis")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

file_handler = RotatingFileHandler(
    "complexity_analysis_individual.log",
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5,  # Keep up to 5 backup log files
)
file_handler.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# ====================================
# Define Feature Extraction Constants
# ====================================

max_values = {
    "permissions_count": 30,
    "native_code_count": 10,
    "obfuscated_strings_count": 50,
    "dynamic_code_use_count": 20,
    "apk_entropy": 8,
    "code_length": 10000,
    "file_size_mb": 100,
}

weights = {
    "permissions_count": 1.0,
    "native_code_count": 1.5,
    "obfuscated_strings_count": 2.0,
    "dynamic_code_use_count": 2.5,
    "apk_entropy": 3.0,
    "code_length": 1.0,
    "file_size_mb": 0.5,
}

# ======================
# Helper Function: Hash
# ======================


def calculate_hash(apk_path, hash_type="sha256"):
    hash_funcs = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}
    h = hash_funcs.get(hash_type)()
    if h is None:
        raise ValueError("Unsupported hash type specified.")

    try:
        with open(apk_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                h.update(byte_block)
        return h.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {apk_path}: {e}")
        return "Hash_Error"


# =====================
# Helper Function: Entropy
# =====================


def entropy(s):
    if not s:
        return 0
    prob = {char: float(s.count(char)) / len(s) for char in set(s)}
    return -sum(prob[char] * math.log(prob[char], 2) for char in prob if prob[char] > 0)


def is_string_obfuscated(string):
    return len(string) > 20 and entropy(string) > 4.5


# ===================================
# Feature Extraction Functions
# ===================================


def extract_obfuscation_features(dexes):
    try:
        return sum(
            1
            for dex in dexes
            for string in dex.get_strings()
            if is_string_obfuscated(string)
        )
    except Exception as e:
        logger.error(f"Error extracting obfuscation features: {e}")
        return 0


def extract_dynamic_code_features(dexes):
    try:
        return sum(
            1
            for dex in dexes
            for method in dex.get_methods()
            if "Ldalvik/system/DexClassLoader;" in str(method.get_class_name())
            or "Ldalvik/system/PathClassLoader;" in str(method.get_class_name())
        )
    except Exception as e:
        logger.error(f"Error extracting dynamic code features: {e}")
        return 0


def calculate_apk_entropy(dexes):
    try:
        total_entropy = sum(
            entropy(string) for dex in dexes for string in dex.get_strings()
        )
        string_count = sum(1 for dex in dexes for _ in dex.get_strings())
        return total_entropy / max(string_count, 1)
    except Exception as e:
        logger.error(f"Error calculating APK entropy: {e}")
        return 0


def calculate_code_length(dexes):
    try:
        return sum(
            len(list(method.get_instructions()))
            for dex in dexes
            for method in dex.get_methods()
            if hasattr(method, "get_code") and method.get_code() is not None
        )
    except Exception as e:
        logger.error(f"Error calculating code length: {e}")
        return 0


# =============================
# Feature Extraction for APK
# =============================


def extract_features(apk_path):
    try:
        a, dexes, dx = AnalyzeAPK(apk_path)
        features = {
            "permissions": len(a.get_permissions()),
            "native_code": len(a.get_libraries()),
            "obfuscated_strings_count": extract_obfuscation_features(dexes),
            "dynamic_code_use_count": extract_dynamic_code_features(dexes),
            "apk_entropy": calculate_apk_entropy(dexes),
            "code_length": calculate_code_length(dexes),
            "file_size_mb": os.path.getsize(apk_path) / (1024 * 1024),  # Convert to MB
            "file_hash": calculate_hash(apk_path, "sha256"),
        }

        del a, dexes, dx
        gc.collect()
        return features
    except Exception as e:
        logger.error(f"Failed to process {apk_path}: {e}")
        return None


# =============================
# Complexity Score Calculation
# =============================


def calculate_complexity_score(features):
    if features is None:
        return 0
    try:
        normalized_features = {
            feature: min(float(features.get(feature, 0)) / max_val, 1)
            for feature, max_val in max_values.items()
        }
        return sum(
            normalized_features[feature] * weights[feature]
            for feature in normalized_features
        )
    except Exception as e:
        logger.error(f"Error calculating complexity score: {e}")
        return 0


# =====================
# APK Processing Function
# =====================


def process_apk_file(apk_path, master_csv):
    features = extract_features(apk_path)
    if features:
        complexity_score = calculate_complexity_score(features)
        result = {
            "apk_path": apk_path,
            "complexity_score": complexity_score,
            "permissions_count": features["permissions"],
            "native_code_count": features["native_code"],
            "obfuscated_strings_count": features["obfuscated_strings_count"],
            "dynamic_code_use_count": features["dynamic_code_use_count"],
            "apk_entropy": features["apk_entropy"],
            "code_length": features["code_length"],
            "file_size_mb": features["file_size_mb"],
            "file_hash": features["file_hash"],
        }
        logger.info(f"Processed {apk_path}: Complexity Score = {complexity_score}")

        # Append the result directly to the master CSV
        try:
            with open(master_csv, "a", newline="", encoding="utf-8") as csvfile:
                fieldnames = [
                    "apk_path",
                    "complexity_score",
                    "permissions_count",
                    "native_code_count",
                    "obfuscated_strings_count",
                    "dynamic_code_use_count",
                    "apk_entropy",
                    "code_length",
                    "file_size_mb",
                    "file_hash",
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                if os.path.getsize(master_csv) == 0:
                    writer.writeheader()
                writer.writerow(result)
        except Exception as e:
            logger.error(f"Error writing to master CSV for {apk_path}: {e}")

        del result
        gc.collect()
    else:
        # Log failed APK processing
        try:
            with open(master_csv, "a", newline="", encoding="utf-8") as csvfile:
                fieldnames = [
                    "apk_path",
                    "complexity_score",
                    "permissions_count",
                    "native_code_count",
                    "obfuscated_strings_count",
                    "dynamic_code_use_count",
                    "apk_entropy",
                    "code_length",
                    "file_size_mb",
                    "file_hash",
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                if os.path.getsize(master_csv) == 0:
                    writer.writeheader()
                writer.writerow(
                    {
                        "apk_path": apk_path,
                        "complexity_score": 0,
                        "permissions_count": "Failed",
                        "native_code_count": "Failed",
                        "obfuscated_strings_count": "Failed",
                        "dynamic_code_use_count": "Failed",
                        "apk_entropy": "Failed",
                        "code_length": "Failed",
                        "file_size_mb": "Failed",
                        "file_hash": "Failed",
                    }
                )
        except Exception as e:
            logger.error(f"Error logging failed APK to master CSV for {apk_path}: {e}")


# =====================
# APK File Generator
# =====================


def apk_file_generator(base_path):
    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".apk"):
                yield os.path.join(root, file)


# =====================
# Main Function
# =====================


def main():
    base_path = "./KronoDroid_Real_Malware_04"  # Update this path as needed
    master_csv = "analysis_results_master.csv"

    logger.info("Starting APK analysis...")

    apk_gen = apk_file_generator(base_path)
    total_apks = sum(1 for _ in apk_file_generator(base_path))
    apk_gen = apk_file_generator(base_path)

    for apk_path in tqdm(apk_gen, total=total_apks, desc="Processing APKs"):
        process_apk_file(apk_path, master_csv)

    logger.info("APK analysis completed.")


if __name__ == "__main__":
    main()
