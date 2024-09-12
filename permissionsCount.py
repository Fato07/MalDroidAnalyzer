import pandas as pd
import ast

def count_permissions(permission_list_string):
    try:
        # Convert the string representation of a list to an actual list
        permissions_list = ast.literal_eval(permission_list_string)
        return len(permissions_list)
    except:
        return 0

def add_permissions_count_and_save(file_path, output_file_path):
    # Load the dataset
    data = pd.read_csv(file_path)
    
    # Add the 'permissions_count' column
    data['permissions_count'] = data['permissions'].apply(count_permissions)
    
    # Save the modified dataset to a new CSV file
    data.to_csv(output_file_path, index=False)
    print(f"File saved successfully to {output_file_path}")

# Example usage:
input_file_path = 'analysis_results.csv'
output_file_path = 'updated_analysis_results.csv'
add_permissions_count_and_save(input_file_path, output_file_path)
