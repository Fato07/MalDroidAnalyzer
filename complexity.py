import math
import os
import time
from androguard.misc import AnalyzeAPK

# Define the maximum expected values for each feature based on your dataset
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

def entropy(s):
    """
    Calculate the entropy of a given string.
    """
    prob = {char: float(s.count(char)) / len(s) for char in dict.fromkeys(list(s))}
    entropy_val = -sum(prob[char] * math.log(prob[char], 2) for char in prob)
    return entropy_val

def is_string_obfuscated(string):
    """
    Determine if a string is likely to be obfuscated based on its entropy.
    """
    return len(string) > 20 and entropy(string) > 4.5

def extract_obfuscation_features(dexes):
    """
    Extract obfuscation-related features from the DEX bytecode.
    """
    obfuscated_strings_count = sum(1 for dex in dexes for string in dex.get_strings() if is_string_obfuscated(string))
    return obfuscated_strings_count

def extract_dynamic_code_features(dexes):
    """
    Detect features related to dynamic code execution in the APK.
    """
    dynamic_code_use = sum(1 for dex in dexes for method in dex.get_methods() if 'Ldalvik/system/DexClassLoader;' in str(method.get_class_name()) or 'Ldalvik/system/PathClassLoader;' in str(method.get_class_name()))
    return dynamic_code_use

def calculate_apk_entropy(dexes):
    """
    Calculate the average entropy of all strings in the APK's DEX files.
    """
    total_entropy = sum(entropy(string) for dex in dexes for string in dex.get_strings())
    string_count = sum(1 for dex in dexes for _ in dex.get_strings())
    return total_entropy / max(string_count, 1)

def calculate_code_length(dexes):
    """
    Calculate the total length of code in all DEX files.
    """
    total_length = 0
    for dex in dexes:
        for method in dex.get_methods():
            if method.get_code():  # Ensure there is a code item
                # Convert the generator to a list to get the length
                instructions = list(method.get_code().get_bc().get_instructions())
                total_length += len(instructions)
    return total_length

def extract_features(apk_path):
    """
    Extract features from the APK file, including permissions and other complexity indicators.
    """
    a, dexes, dx = AnalyzeAPK(apk_path)
    permissions = a.get_permissions()
    native_code = a.get_libraries()
    obfuscated_strings_count = extract_obfuscation_features(dexes)
    dynamic_code_use = extract_dynamic_code_features(dexes)
    apk_entropy = calculate_apk_entropy(dexes)
    code_length = calculate_code_length(dexes)
    file_size_bytes = os.path.getsize(apk_path)

    return {
        "permissions": permissions,
        "native_code": native_code,
        "obfuscated_strings_count": obfuscated_strings_count,
        "dynamic_code_use": dynamic_code_use,
        "apk_entropy": apk_entropy,
        "code_length": code_length,
        "file_size": file_size_bytes,
    }

def analyze_complexity(features):
    """
    Analyze the complexity of the APK based on extracted features.
    """
    complexity_score = len(features["permissions"])
    complexity_score += len(features["native_code"])
    complexity_score += features["obfuscated_strings_count"]
    complexity_score += features["dynamic_code_use"]
    complexity_score += features["apk_entropy"]  # Consider scaling this value if needed
    complexity_score += math.log(features["file_size"], 2)  # Log of file size to normalize large numbers
    # complexity_score += features["file_size_mb"]
    complexity_score += features["code_length"] / 1000  # Normalize code length to prevent it from dominating the score
    return complexity_score

def normalize(value, max_value):
    """
    Normalize the feature value to a scale of 0 to 1.
    """
    return min(float(value) / max_value, 1)

def calculate_complexity_score(features, weights, max_values):
    """
    Calculate the complexity score using normalized features and assigned weights.
    """
    # Normalize features
    normalized_features = {feature: normalize(value, max_values[feature]) for feature, value in features.items() if feature in max_values}
    
    # Calculate the weighted sum of features
    complexity_score = sum(normalized_features[feature] * weights[feature] for feature in normalized_features)
    
    return complexity_score

def process_apk_files(base_path):
    """
    Process each APK file in the given directory and its subdirectories.
    """
    results = []
    for root, dirs, files in os.walk(base_path):
        print(f"Checking directory: {root}")  # Debug information
        for file in files:
            print(f"Found file: {file}") 
            if file.endswith(".apk"):
                apk_path = os.path.join(root, file)
                start_time = time.time()
                features = extract_features(apk_path)

                # Normalize file size to MB for the features dictionary
                features["file_size_mb"] = features["file_size"] / (1024 * 1024)
                # Use the normalized file size for complexity calculation
                features["file_size"] = features["file_size_mb"]

                # Calculate the complexity score
                complexity_score = calculate_complexity_score(features, weights, max_values)

                analysis_time = time.time() - start_time
                results.append({
                    "apk_path": apk_path,
                    "complexity_score": complexity_score,
                    "analysis_time": analysis_time,
                    "permissions_count": len(features["permissions"]),
                    "native_code_count": len(features["native_code"]),
                    "obfuscated_strings_count": features["obfuscated_strings_count"],
                    "dynamic_code_use_count": features["dynamic_code_use"],
                    "apk_entropy": features["apk_entropy"],
                    "code_length": features["code_length"],
                    "file_size": features["file_size"],
                })
                print(f"{apk_path}: Complexity Score - {complexity_score}, Analysis Time - {analysis_time} seconds")
                print(f"Permissions Count - {len(features['permissions'])}")
                print(f"Native Code Count - {len(features['native_code'])}")
                print(f"Obfuscated Strings Count - {features['obfuscated_strings_count']}")
                print(f"Dynamic Code Use Count - {features['dynamic_code_use']}")
                print(f"APK Entropy - {features['apk_entropy']}")
                print(f"Code Length - {features['code_length']}")
                print(f"APK File Size - {features['file_size']} MB\n")
    return results

def export_results(results, filename="analysis_results.csv"):
    
    if not results:  # Check if results is empty
        print("No results to export.")
        return
    
    """
    Save the analysis results to a CSV file.
    """
    import csv
    keys = results[0].keys()
    with open(filename, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)

def main():
    base_path = "./AndroidMalwareSamples"
    results = process_apk_files(base_path)
    export_results(results)

if __name__ == "__main__":
    main()
