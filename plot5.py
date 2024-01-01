import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
file_path = 'analysis_results_with_dates_and_family.csv' 

data = pd.read_csv(file_path)

# Categorizing the dataset into benign and malware groups
benign_data = data[data['label'] == 'benign']
malware_data = data[data['label'] == 'malware']

# Calculating descriptive statistics for both groups
benign_stats = benign_data['complexity_score'].describe()
malware_stats = malware_data['complexity_score'].describe()

# Setting up the plotting style
sns.set(style="whitegrid")

# Plotting the distributions
plt.figure(figsize=(14, 6))

# Benign samples distribution
plt.subplot(1, 2, 1)
sns.histplot(benign_data['complexity_score'], kde=True, color="skyblue", edgecolor="black")
plt.axvline(benign_data['complexity_score'].mean(), color='blue', linestyle='dashed', linewidth=1)
plt.title('Distribution of Complexity Scores for Benign Samples')
plt.xlabel('Complexity Score')
plt.ylabel('Frequency')

# Malware samples distribution
plt.subplot(1, 2, 2)
sns.histplot(malware_data['complexity_score'], kde=True, color="salmon", edgecolor="black")
plt.axvline(malware_data['complexity_score'].mean(), color='red', linestyle='dashed', linewidth=1)
plt.title('Distribution of Complexity Scores for Malware Samples')
plt.xlabel('Complexity Score')
plt.ylabel('Frequency')

plt.tight_layout()
plt.show()

# Printing the descriptive statistics
print("Benign Samples Statistics:\n", benign_stats)
print("\nMalware Samples Statistics:\n", malware_stats)