import gc
import os
import hashlib
import csv
import logging
from logging.handlers import RotatingFileHandler
from androguard.misc import AnalyzeAPK
import androguard
from tqdm import tqdm
import time
import math

print(f"Using androguard version: {androguard.__version__}")

# ============================
# Logging Setup with Rotation
# ============================

# Set root logger to DEBUG
logging.getLogger().setLevel(logging.DEBUG)

logger = logging.getLogger("APKAnalysis")
logger.setLevel(logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

file_handler = RotatingFileHandler(
    "complexity_analysis_individual.log",
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=5,  # Keep up to 5 backup log files
)
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# ====================================
# Define Feature Extraction Constants
# ====================================

max_values = {
    "permissions_count": 50,          
    "native_code_count": 10,          
    "obfuscated_strings_count": 50,   
    "dynamic_code_use_count": 20,     
    "apk_entropy": 8.0,              
    "code_length": 20000,          
    "file_size_mb": 100,            
}

weights = {
    "permissions_count": 1.0,         
    "native_code_count": 2.0,          
    "obfuscated_strings_count": 1.5,  
    "dynamic_code_use_count": 2.0,   
    "apk_entropy": 1.0,             
    "code_length": 1.5,              
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
    """Enhanced obfuscation detection with more sophisticated checks"""
    try:
        # Convert to string if bytes
        if isinstance(string, bytes):
            string = string.decode("utf-8", errors="ignore")

        # Skip empty or very short strings
        if not string or len(string) < 4:
            return False

        # Skip common Android/Java patterns
        common_patterns = [
            "android.",
            "java.",
            "javax.",
            "com.android.",
            "onCreate",
            "onResume",
            "onPause",
            "activity_",
            "layout_",
            "text_",
            "button_",
        ]
        if any(pattern in string for pattern in common_patterns):
            return False

        # Enhanced entropy check with length consideration
        str_entropy = entropy(string)
        if len(string) > 20:
            return str_entropy > 4.5
        elif len(string) > 10:
            return str_entropy > 4.0
        else:
            return str_entropy > 3.5

    except Exception as e:
        logger.debug(f"Error in is_string_obfuscated: {e}")
        return False


# ===================================
# Feature Extraction Functions
# ===================================

def extract_obfuscation_features(dexes):
    """Improved obfuscation feature extraction"""
    try:
        obfuscated_count = 0
        total_strings = 0

        for dex in dexes:
            strings = dex.get_strings()
            for string in strings:
                total_strings += 1
                if is_string_obfuscated(string):
                    obfuscated_count += 1

                    # Early exit if we've found enough obfuscated strings
                    if obfuscated_count >= max_values["obfuscated_strings_count"]:
                        logger.debug(
                            f"Max obfuscated strings reached: {obfuscated_count}"
                        )
                        return obfuscated_count

        logger.debug(
            f"Found {obfuscated_count} obfuscated strings out of {total_strings}"
        )
        return obfuscated_count

    except Exception as e:
        logger.error(f"Error extracting obfuscation features: {e}")

def extract_native_code_features(a, dx):
    """Detect native code by checking for .so files in lib directory"""
    try:
        logger.debug("Starting native code feature extraction")
        native_libraries = a.get_libraries()
        logger.debug(f"Found native libraries: {native_libraries}")
        return len(native_libraries)
    except Exception as e:
        logger.error(f"Error extracting native code features: {e}")
        logger.exception("Detailed error trace:")
        return 0
    
def extract_dynamic_code_features(dx):
    """Look for dynamic code loading patterns in strings"""
    try:
        logger.debug("Starting dynamic code feature extraction")
        dynamic_patterns = [
            "DexClassLoader",
            "PathClassLoader",
            "BaseDexClassLoader",
            "loadClass",
            "loadLibrary",
            "reflect.Method",
            "invoke"
        ]
        
        count = 0
        # Search in method names
        for method in dx.get_methods():
            method_name = str(method.name)
            if any(pattern.lower() in method_name.lower() for pattern in dynamic_patterns):
                logger.debug(f"Found dynamic code pattern in method: {method_name}")
                count += 1
                    
        logger.debug(f"Total dynamic code features found: {count}")
        return count
    except Exception as e:
        logger.error(f"Error extracting dynamic code features: {e}")
        logger.exception("Detailed error trace:")
        return 0 
    
def calculate_apk_entropy(dexes):
    try:
        logger.debug("Starting APK entropy calculation")
        total_weighted_entropy = 0
        total_weight = 0

        for dex in dexes:
            logger.debug(f"Processing DEX file for entropy calculation")

            # Calculate entropy for different sections with different weights
            sections = {
                "strings": {"data": [str(s) for s in dex.get_strings()], "weight": 1.0},
                "classes": {"data": [str(c) for c in dex.get_classes()], "weight": 1.2},
                "methods": {"data": [str(m) for m in dex.get_methods()], "weight": 1.5},
            }

            for section_name, section_data in sections.items():
                try:
                    data = section_data["data"]
                    logger.debug(f"Section {section_name} has {len(data)} elements")

                    combined_data = "".join(data)
                    if combined_data:
                        section_entropy = entropy(combined_data)
                        weight = section_data["weight"]

                        total_weighted_entropy += section_entropy * weight
                        total_weight += weight

                        logger.debug(
                            f"Section {section_name} entropy: {section_entropy:.2f} with weight {weight}"
                        )
                    else:
                        logger.debug(f"Section {section_name} has no data to process")

                except Exception as section_e:
                    logger.error(
                        f"Error processing {section_name} section: {section_e}"
                    )
                    logger.exception("Detailed section error:")
                    continue

        if total_weight == 0:
            logger.warning("No valid sections found for entropy calculation")
            return 0

        final_entropy = total_weighted_entropy / total_weight
        final_entropy = min(max(final_entropy, 0), 8)

        logger.debug(f"Final weighted entropy: {final_entropy:.2f}")
        return final_entropy

    except Exception as e:
        logger.error(f"Error calculating APK entropy: {e}")
        logger.exception("Detailed error trace:")
        return 0

def calculate_code_length(dx):
    """Simple count of DEX methods as a proxy for code length"""
    try:
        logger.debug("Starting code length calculation")
        total_methods = 0
        
        for method in dx.get_methods():
            total_methods += 1
            if total_methods % 100 == 0:
                logger.debug(f"Processed {total_methods} methods...")
        
        logger.debug(f"Total methods found: {total_methods}")
        return total_methods
    except Exception as e:
        logger.error(f"Error calculating code length: {e}")
        logger.exception("Detailed error trace:")
        return 0
      
def extract_features(apk_path):
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        if not d:
            logger.warning(f"No dex files found in {apk_path}")
            return None

        # Validate analysis object
        if not dx:
            logger.warning(f"Failed to create analysis object for {apk_path}")
            return None

        features = {
            "permissions": len(a.get_permissions()),
            "native_code": extract_native_code_features(a, dx),
            "obfuscated_strings_count": extract_obfuscation_features(d),
            "dynamic_code_use_count": extract_dynamic_code_features(dx),
            "apk_entropy": calculate_apk_entropy(d),
            "code_length": calculate_code_length(dx),
            "file_size_mb": os.path.getsize(apk_path) / (1024 * 1024),
            "file_hash": calculate_hash(apk_path, "sha256"),
        }

        del a, d, dx
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


def main(resume=False):
    base_path = "/Users/fathindosunmu/Downloads/KronoDroid_Real_Malware_01"  # Update this path as needed
    master_csv = "analysis_results_master.csv"

    # Verify logging level
    logger.debug("Debug logging is enabled")
    logger.info("Starting APK analysis...")

    processed_apks = set()
    if resume and os.path.exists(master_csv):
        try:
            with open(master_csv, "r", newline="", encoding="utf-8") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    processed_apks.add(row["apk_path"])
            logger.info(f"Resuming from {len(processed_apks)} processed APKs.")
        except Exception as e:
            logger.error(f"Error reading existing master CSV file: {e}")

    apk_gen = apk_file_generator(base_path)
    total_apks = sum(1 for _ in apk_file_generator(base_path))
    apk_gen = apk_file_generator(base_path)

    for apk_path in tqdm(apk_gen, total=total_apks, desc="Processing APKs"):
        if apk_path in processed_apks:
            logger.info(f"Skipping already processed APK: {apk_path}")
            continue
        process_apk_file(apk_path, master_csv)

    logger.info("APK analysis completed.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="APK Analysis Script")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume analysis from the last processed APK",
    )
    args = parser.parse_args()

    main(resume=args.resume)
