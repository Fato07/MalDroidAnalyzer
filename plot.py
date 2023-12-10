import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Load your data
data = pd.read_csv('analysis_results.csv')

numeric_features = ['complexity_score', 'analysis_time', 'permissions_count', 
                    'obfuscated_strings_count', 'apk_entropy', 'code_length', 'file_size']

# Include the 'label' column for plotting and filtering
numeric_data = data[numeric_features + ['label']]

# Set the style of the visualization
sns.set(style="whitegrid")

# Iterate over numeric features and create separate scatter plots
for feature in numeric_features:
    plt.figure(figsize=(8, 6))
    sns.scatterplot(x='complexity_score', y=feature, hue='label', data=data, palette="Set1", s=60)
    plt.title(f'Complexity Score vs {feature}', fontsize=15)
    plt.xlabel('Complexity Score', fontsize=12)
    plt.ylabel(feature, fontsize=12)
    plt.savefig(f'scatter_plot_{feature}.png')  # Saves each plot as a separate file
    plt.close()  # Close the plot to free up memory
    

# Filter only malware data for the heatmap
malware_data = numeric_data[numeric_data['label'] == 'malware'].drop('label', axis=1)
correlation_matrix = malware_data.corr()

plt.figure(figsize=(12, 10))
sns.set(style="white")
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', linewidths=.5, cbar_kws={"shrink": .5})
plt.title("Correlation Heatmap for Malware Samples", fontsize=18)
plt.xticks(fontsize=10)
plt.yticks(fontsize=10)
plt.savefig('heatmap_pretty.png')
