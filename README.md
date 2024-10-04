# MalDroidAnalyzer

## Overview
MalDroidAnalyzer is a tool designed to analyze Android malware datasets. It provides insights into the complexity and behavior of malware samples.

## Prerequisites
- Python 3.x
- Required Python packages (listed in `requirements.txt`)

## Setup
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Fato07/MalDroidAnalyzer.git
   cd MalDroidAnalyzer
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Download the Malware Dataset:**
   - Download the malware folder from the provided source.

4. **Configure the Path:**
   - Replace the path in `complexity.py` with the path to your downloaded malware folder.

## Running the Project
1. **Run the Analyzer:**
   ```bash
   python complexity.py
   ```

2. **View Results:**
   - The results will be output to the console or saved to a specified file, depending on the configuration in `complexity.py`.

## Additional Information
- For more detailed usage and options, refer to the comments within `complexity.py`.
- Ensure that your dataset is properly structured as expected by the script.
