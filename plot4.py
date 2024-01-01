import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
file_path = 'analysis_results_with_dates_and_family.csv'
data = pd.read_csv(file_path)

# Convert 'first_submission_date' to datetime and extract the year
data['first_submission_date'] = pd.to_datetime(data['first_submission_date'], errors='coerce')
data = data.dropna(subset=['first_submission_date'])
data['year'] = data['first_submission_date'].dt.year

# Group by malware family and year, calculate average complexity
grouped_data = data.groupby(['malware_family', 'year'])['complexity_score'].mean().reset_index()

# Pivot the data for plotting
pivot_data = grouped_data.pivot(index='year', columns='malware_family', values='complexity_score')

# Select a subset of malware families for clarity
selected_families = pivot_data.columns[:10]  # Adjust the number as needed
filtered_pivot_data = pivot_data[selected_families]

# Resizing the plot for a MS Word document
plt.figure(figsize=(8, 6))  # Adjust the size as needed

# Plotting
sns.lineplot(data=filtered_pivot_data)

# Titles and labels
plt.title('Evolution of Selected Malware Family Complexities Over Time')
plt.ylabel('Average Complexity')
plt.xlabel('Year')

# Adjusting the legend to fit in the plot
plt.legend(title='Malware Family', loc='upper right')  # Adjust the location as needed

plt.tight_layout()
plt.show()