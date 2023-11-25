import seaborn as sns

# Enhanced bar chart
sns.set(style="whitegrid")
plt.figure(figsize=(10, 6))
bar_plot = sns.barplot(x=features, y=weights, palette="Blues_d")
plt.xlabel('Features')
plt.ylabel('Assigned Weights')
plt.title('Bar Graph of Complexity Score Calculation Factors')
plt.xticks(rotation=45)
plt.show()

# Enhanced bubble chart
plt.figure(figsize=(10, 6))
bubble_sizes = [weight * 1000 for weight in weights]  # Scale up the weights for bubble size
colors = sns.color_palette("Blues", as_cmap=True)
plt.scatter(features, normalized_complexity, s=bubble_sizes, c=range(len(features)), cmap='Blues', alpha=0.6, edgecolors="w", linewidth=2)
plt.xlabel('Features')
plt.ylabel('Normalized Complexity Scores')
plt.title('Bubble Chart of Complexity Score Calculation Factors')
plt.xticks(rotation=45)
plt.colorbar()  # Show color scale
plt.show()

import plotly.graph_objects as go

# Enhanced radar chart with Plotly
categories = features
fig = go.Figure()

fig.add_trace(go.Scatterpolar(
      r=weights,
      theta=categories,
      fill='toself',
      name='Feature Weights'
))

fig.update_layout(
  polar=dict(
    radialaxis=dict(
      visible=True,
      range=[0, max(weights)]
    )),
  showlegend=False
)

fig.show()

# Enhanced heatmap
sns.set(style="white")

# Assuming 'data_matrix' is a 2D array of shape (n_samples, n_features) with normalized weights
# Here we create a sample data matrix for illustration
np.random.seed(0)
data_matrix = np.random.rand(10, len(features))  # 10 samples and weights for each feature

# Create a custom colormap
cmap = sns.diverging_palette(220, 20, as_cmap=True)
sns.heatmap(data_matrix, cmap=cmap, annot=True, fmt=".2f",
            xticklabels=features, yticklabels=["Sample {}".format(i) for i in range(1, 11)])
plt.title('Heatmap of Feature Weights across Samples')
plt.xticks(rotation=45)
plt.show()

