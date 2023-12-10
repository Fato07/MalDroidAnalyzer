import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.ticker import MaxNLocator

# Path to the CSV file
csv_file_path = 'analysis_results_with_dates.csv'  # Make sure this points to your CSV

# Read the CSV file
data = pd.read_csv(csv_file_path)

# Replace 'Not found' or any other invalid date formats with NaN
data['first_submission_date'] = data['first_submission_date'].replace('Not found', pd.NaT)

# Convert 'first_submission_date' to datetime, invalid parsing will be set as NaT
data['first_submission_date'] = pd.to_datetime(data['first_submission_date'], errors='coerce')

# You might want to drop or handle rows with NaT in 'first_submission_date'
data = data.dropna(subset=['first_submission_date'])
# Filter out the malware samples
malware_data = data[data['label'] == 'malware']

# Sorting the data by 'first_submission_date'
malware_data_sorted = malware_data.sort_values('first_submission_date')

# Create a smoother line using a rolling average
malware_data_sorted['rolling_avg'] = malware_data_sorted['complexity_score'].rolling(window=5).mean()

# Plotting Complexity Score over Time for Malware Samples with enhancements
plt.figure(figsize=(14, 7))
sns.set_style("whitegrid")
sns.scatterplot(x='first_submission_date', y='complexity_score', data=malware_data_sorted, color='skyblue', label='Actual Score')
sns.lineplot(x='first_submission_date', y='rolling_avg', data=malware_data_sorted, color='darkblue', label='Rolling Avg (window=5)')
sns.regplot(x=mdates.date2num(malware_data_sorted['first_submission_date']), y='complexity_score', data=malware_data_sorted, scatter=False, color='red', label='Trend Line')
plt.title('Complexity Score over Time for Malware Samples', fontsize=20)
plt.xlabel('First Submission Date', fontsize=16)
plt.ylabel('Complexity Score', fontsize=16)
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout()
plt.savefig('./Figures/complexity_score_over_time.png')
plt.show()

# Histogram of Complexity Scores
plt.figure(figsize=(14, 7))
sns.histplot(malware_data_sorted['complexity_score'], kde=True, color='skyblue')
plt.title('Distribution of Complexity Scores for Malware Samples', fontsize=20)
plt.xlabel('Complexity Score', fontsize=16)
plt.ylabel('Frequency', fontsize=16)
plt.tight_layout()
plt.savefig('./Figures/complexity_score_distribution.png')
plt.show()

# Boxplot of Complexity Scores by Year
malware_data_sorted['year'] = malware_data_sorted['first_submission_date'].dt.year
plt.figure(figsize=(14, 7))
sns.boxplot(x='year', y='complexity_score', data=malware_data_sorted, palette="cool")
plt.title('Complexity Score by Year for Malware Samples', fontsize=20)
plt.xlabel('Year', fontsize=16)
plt.ylabel('Complexity Score', fontsize=16)
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('./Figures/complexity_score_by_year.png')
plt.show()

print(malware_data_sorted)