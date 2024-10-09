# process_single_apk.py

import sys
import gc
import math
import os
import hashlib
import csv
import logging
from androguard.misc import AnalyzeAPK

# =======================
# Logging Setup
# =======================

# Create a logger
logger = logging.getLogger("SingleAPKProcessor")
logger.setLevel(logging.DEBUG)  # Set to DEBUG for detailed logs

# Create console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)  # Capture all logs in the console

# Define log formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)

# Add handler to logger
logger.addHandler(console_handler)

# =======================
# Feature Extraction Constants
# =======================

# Maximum expected values for normalization
max_values = {
    "permissions_count": 30,
    "native_code_count": 10,
    "obfuscated_strings_count": 50,
    "dynamic_code_use_count": 20,
    "apk_entropy": 8,
    "code_length": 10000,
    "file_size_mb": 100,
}

# Weights for each feature
weights = {
    "permissions_count": 1.0,
    "native_code_count": 1.5,
    "obfuscated_strings_count": 2.0,
    "dynamic_code_use_count": 2.5,
    "apk_entropy": 3.0,
    "code_length": 1.0,
    "file_size_mb": 0.5,
}

# =======================
# Helper Functions
# =======================


def calculate_hash(apk_path, hash_type="sha256"):
    """
    Calculate the hash of the APK file using md5, sha1, or sha256.
    """
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


def entropy(s):
    """
    Calculate the Shannon entropy of a given string.
    """
    if not s:
        return 0
    prob = {char: float(s.count(char)) / len(s) for char in set(s)}
    return -sum(prob[char] * math.log(prob[char], 2) for char in prob if prob[char] > 0)


def is_string_obfuscated(string):
    """
    Determine if a string is likely to be obfuscated based on its entropy.
    """
    return len(string) > 20 and entropy(string) > 4.5


def extract_obfuscation_features(dexes):
    """
    Extract obfuscation-related features from the DEX bytecode.
    """
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
    """
    Detect dynamic code execution features in the APK.
    """
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
    """
    Calculate the average entropy of all strings in the APK's DEX files.
    """
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
    """
    Calculate the total length of code in all DEX files.
    """
    try:
        return sum(
            len(list(method.get_code().get_bc().get_instructions()))
            for dex in dexes
            for method in dex.get_methods()
            if method.get_code()
        )
    except Exception as e:
        logger.error(f"Error calculating code length: {e}")
        return 0


# =======================
# Feature Extraction
# =======================


def extract_features(apk_path):
    """
    Extract relevant features from the APK file.
    """
    try:
        a, dexes, dx = AnalyzeAPK(apk_path)
        features = {
            "permissions": ";".join(a.get_permissions()),
            "permissions_count": len(a.get_permissions()),
            "native_code": ";".join(a.get_libraries()),
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
        logger.error(f"Failed to process {apk_path}: {e}")
        return None


# =======================
# Complexity Score Calculation
# =======================


def calculate_complexity_score(features):
    """
    Calculate the complexity score using normalized features and assigned weights.
    """
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


# =======================
# Main Function
# =======================


def main():
    if len(sys.argv) != 3:
        logger.error("Usage: python process_single_apk.py <apk_path> <output_csv_path>")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_csv = sys.argv[2]

    if not os.path.exists(apk_path):
        logger.error(f"APK file does not exist: {apk_path}")
        sys.exit(1)

    logger.info(f"Starting processing for APK: {apk_path}")
    features = extract_features(apk_path)
    if features:
        complexity_score = calculate_complexity_score(features)
        result = {
            "apk_path": apk_path,
            "label": "malware" if "malware" in apk_path.lower() else "benign",
            "complexity_score": complexity_score,
            "permissions": features["permissions"],
            "permissions_count": features["permissions_count"],
            "native_code": features["native_code"],
            "native_code_count": features["native_code_count"],
            "obfuscated_strings_count": features["obfuscated_strings_count"],
            "dynamic_code_use_count": features["dynamic_code_use_count"],
            "apk_entropy": features["apk_entropy"],
            "code_length": features["code_length"],
            "file_size_mb": features["file_size_mb"],
            "file_hash": features["file_hash"],
        }

        try:
            with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
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
                writer.writeheader()
                writer.writerow(result)
            logger.info(f"Successfully processed and saved {apk_path} to {output_csv}")
        except Exception as e:
            logger.error(f"Error writing CSV for {apk_path}: {e}")
    else:
        logger.error(f"No features extracted for {apk_path}")


if __name__ == "__main__":
    main()
