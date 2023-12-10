import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load the dataset
data = pd.read_csv('analysis_results_with_dates.csv')

# Replace 'Not found' or any other invalid date formats with NaN
data['first_submission_date'] = data['first_submission_date'].replace('Not found', pd.NaT)

# Convert 'first_submission_date' to datetime, invalid parsing will be set as NaT
data['first_submission_date'] = pd.to_datetime(data['first_submission_date'], errors='coerce')

# Drop rows with NaT in 'first_submission_date'
data = data.dropna(subset=['first_submission_date'])
# Filter out the malware samples
malware_data = data[data['label'] == 'malware']

# Sorting the data by 'first_submission_date'
malware_data_sorted = malware_data.sort_values('first_submission_date')

# Extracting year from 'first_submission_date' for grouping
malware_data_sorted['year'] = malware_data_sorted['first_submission_date'].dt.year

# For the heatmap, we need to create a pivot table where columns are years and rows are features
features = ['permissions_count', 'obfuscated_strings_count', 'apk_entropy', 'code_length', 'file_size']
heatmap_data = malware_data_sorted.pivot_table(index='year', values=features, aggfunc='mean')

# Creating the heatmap
plt.figure(figsize=(10, 8))
heatmap_plot = sns.heatmap(heatmap_data, cmap="YlGnBu", annot=True, fmt=".2f")
plt.title('Heatmap of Feature Evolution over Years')
plt.ylabel('Year')
plt.xlabel('Features', fontsize=14)
plt.xticks(rotation=15)
plt.savefig('heatmap_of_feature_evolution_over_years.png')
plt.show()
