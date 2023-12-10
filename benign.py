import os
import pandas as pd
from androguard.misc import AnalyzeAPK

def extract_features(apk_path):
    # Analyze the APK file
    a, d, dx = AnalyzeAPK(apk_path)

    # Extract features
    features = {
        "filename": os.path.basename(apk_path),
        "permissions": a.get_permissions(),
        "activities": a.get_activities(),
        "services": a.get_services()
    }

    return features

def main():
    apk_directory = './AndroidAPKSamples/Benign'
    features_list = []

    # Iterate over APK files and extract features
    for apk_file in os.listdir(apk_directory):
        if apk_file.endswith('.apk'):
            apk_path = os.path.join(apk_directory, apk_file)
            features = extract_features(apk_path)
            features_list.append(features)

    # Convert to DataFrame
    df = pd.DataFrame(features_list)

    # Save to CSV
    df.to_csv('extracted_features.csv', index=False)

if __name__ == "__main__":
    main()
