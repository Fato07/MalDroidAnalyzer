import gc
import math
import os
import hashlib
import csv
import logging
from logging.handlers import RotatingFileHandler
from androguard.misc import AnalyzeAPK
from tqdm import tqdm
import glob
import psutil
import time

# ============================
# Logging Setup with Rotation
# ============================

# Create a logger
logger = logging.getLogger("APKAnalysis")
logger.setLevel(logging.INFO)

# Create console handler for INFO level
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# Create rotating file handler for INFO level
file_handler = RotatingFileHandler(
    "complexity_analysis_individual.log",
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5,  # Keep up to 5 backup log files
)
file_handler.setLevel(logging.INFO)

# Define log formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

# Add formatter to handlers
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# ====================================
# Define Feature Extraction Constants
# ====================================

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

# ======================
# Helper Function: Hash
# ======================


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


# =====================
# Helper Function: Entropy
# =====================


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


# ===================================
# Feature Extraction Functions
# ===================================


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


# =============================
# Feature Extraction for APK
# =============================


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


# =============================
# Complexity Score Calculation
# =============================


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


# =====================
# APK Processing Function
# =====================


def process_apk_file(apk_path, retries=3, delay=5):
    """
    Process an individual APK file with retry mechanism.
    """
    for attempt in range(1, retries + 1):
        try:
            label = "malware" if "malware" in apk_path.lower() else "benign"
            features = extract_features(apk_path)
            if features:
                complexity_score = calculate_complexity_score(features)
                result = {
                    "apk_path": apk_path,
                    "label": label,
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
                logger.info(
                    f"Processed {apk_path}: Complexity Score = {complexity_score}"
                )
                return result
            else:
                logger.error(f"Skipping {apk_path} due to extraction errors.")
                return None
        except Exception as e:
            logger.error(f"Attempt {attempt} failed for {apk_path}: {e}")
            if attempt < retries:
                logger.info(f"Retrying {apk_path} after {delay} seconds...")
                time.sleep(delay)
            else:
                logger.error(f"All {retries} attempts failed for {apk_path}. Skipping.")
                return None


# =====================
# APK File Generator
# =====================


def apk_file_generator(base_path):
    """
    Generator to yield APK file paths.
    """
    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".apk"):
                yield os.path.join(root, file)


# ============================
# Individual APK Processing
# ============================


def process_apk_files_individual(
    base_path, output_dir="individual_outputs", master_csv="analysis_results_master.csv"
):
    """
    Process each APK individually, save results to individual CSV files, and concatenate them.
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Created directory for individual outputs: {output_dir}")

    # Track already processed APKs to avoid reprocessing
    processed_apks = set()
    if os.path.exists(master_csv):
        try:
            with open(master_csv, "r", newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    processed_apks.add(row["apk_path"])
            logger.info(
                f"Found {len(processed_apks)} already processed APKs in {master_csv}."
            )
        except Exception as e:
            logger.error(f"Error reading existing master CSV file: {e}")

    # Iterate through each APK with a progress bar
    apk_gen = apk_file_generator(base_path)
    total_apks = sum(1 for _ in apk_file_generator(base_path))
    # Reset generator
    apk_gen = apk_file_generator(base_path)

    for apk_path in tqdm(
        apk_gen, total=total_apks, desc="Processing APKs Individually"
    ):
        if apk_path in processed_apks:
            logger.info(f"Skipping already processed APK: {apk_path}")
            continue

        result = process_apk_file(apk_path)
        if result:
            # Create a unique filename based on the APK name or hash
            apk_name = os.path.splitext(os.path.basename(apk_path))[0]
            individual_csv = os.path.join(output_dir, f"{apk_name}.csv")

            # Write the result to the individual CSV
            try:
                with open(individual_csv, "w", newline="", encoding="utf-8") as csvfile:
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
                logger.info(
                    f"Saved individual result for {apk_path} to {individual_csv}"
                )
            except Exception as e:
                logger.error(f"Error writing individual CSV for {apk_path}: {e}")

            # Clean up memory after each APK
            del result
            gc.collect()

    # Concatenate all individual CSVs into a master CSV
    concatenate_individual_csvs(output_dir, master_csv)


# ============================
# Concatenate Individual CSVs
# ============================


def concatenate_individual_csvs(individual_dir, master_csv):
    """
    Concatenate all individual CSV files into a master CSV.
    """
    try:
        # Get list of all individual CSV files
        csv_files = glob.glob(os.path.join(individual_dir, "*.csv"))
        if not csv_files:
            logger.error(f"No individual CSV files found in {individual_dir}.")
            return

        # Open the master CSV file
        with open(master_csv, "a", newline="", encoding="utf-8") as master_file:
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
            writer = csv.DictWriter(master_file, fieldnames=fieldnames)

            # If master CSV is empty, write header
            if os.path.getsize(master_csv) == 0:
                writer.writeheader()

            # Iterate through each individual CSV and append its rows to the master CSV
            for csv_file in tqdm(csv_files, desc="Concatenating Individual CSVs"):
                try:
                    with open(
                        csv_file, "r", newline="", encoding="utf-8"
                    ) as individual_file:
                        reader = csv.DictReader(individual_file)
                        for row in reader:
                            writer.writerow(row)
                except Exception as e:
                    logger.error(f"Error reading individual CSV {csv_file}: {e}")

        logger.info(
            f"All individual CSV files have been concatenated into {master_csv}"
        )
    except Exception as e:
        logger.error(f"Error during concatenation of CSV files: {e}")


# =====================
# Memory Monitoring (Optional)
# =====================


def log_memory_usage():
    """
    Log the current memory usage of the script.
    """
    process = psutil.Process(os.getpid())
    mem = process.memory_info().rss / (1024 * 1024)  # Convert to MB
    logger.info(f"Current memory usage: {mem:.2f} MB")


# =====================
# Main Function
# =====================


def main():
    base_path = "./KronoDroid_Real_Malware_03"  # Update this path as needed
    output_dir = "individual_outputs"
    master_csv = "analysis_results_master.csv"

    logger.info("Starting APK analysis...")

    # Process APK files individually and concatenate results
    process_apk_files_individual(
        base_path, output_dir=output_dir, master_csv=master_csv
    )

    logger.info("APK analysis and concatenation completed.")


if __name__ == "__main__":
    main()
