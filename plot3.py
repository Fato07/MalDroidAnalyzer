import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
file_path = 'analysis_results_with_dates_and_family.csv'  # Replace with your file path
data = pd.read_csv(file_path)

# # Configure pandas to display all rows
# pd.set_option('display.max_rows', None)

# # Counting the number of samples for each malware family
# sample_counts_per_family = data['malware_family'].value_counts().reset_index()
# sample_counts_per_family.columns = ['Malware Family', 'Number of Samples']

# # Optionally, you can sort the data
# sample_counts_per_family = sample_counts_per_family.sort_values(by='Number of Samples', ascending=False)

# # Displaying the full table
# print(sample_counts_per_family)

# Exclude 'Unknown' family
filtered_data = data[data['malware_family'] != 'Unknown']

# Group by malware_family and calculate statistics (using filtered_data)
family_complexity_stats = filtered_data.groupby('malware_family')['complexity_score'].agg(['mean', 'min', 'max'])
family_complexity_stats.rename(columns={'mean': 'Average Complexity', 'min': 'Minimum Complexity', 'max': 'Maximum Complexity'}, inplace=True)

# Sorting data for a better visualization
sorted_data = family_complexity_stats.sort_values(by='Average Complexity', ascending=True)

# Setting up the plotting environment
sns.set(style="whitegrid")
plt.figure(figsize=(8, 10))

# Creating the plot
plt.barh(sorted_data.index, sorted_data['Maximum Complexity'], color='lightblue', label='Max Complexity')
plt.barh(sorted_data.index, sorted_data['Minimum Complexity'], color='navy', label='Min Complexity')
plt.barh(sorted_data.index, sorted_data['Average Complexity'], color='red', label='Average Complexity')

# Adding labels, title, and grid
plt.xlabel('Complexity Score')
plt.ylabel('Malware Family')
plt.title('Complexity Analysis of Malware Families')
plt.legend()
plt.grid(True, linestyle='--', alpha=0.7)

# Enhancements for aesthetics
plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)
plt.tight_layout()

# Show the plot
plt.show()
