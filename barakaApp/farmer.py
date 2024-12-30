import os
import django

# Set up Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'barakaProject.settings')  # Replace with your actual settings module
django.setup()

import pandas as pd
from barakaApp.models import Farmer

# Path to the uploaded file
file_path = 'C:/Users/BraIT/Downloads/Copy of Brms Farmers- milling system excel.xlsx'

# Load the Excel file
try:
    df = pd.read_excel(file_path)

    # Assuming the 'Alias' column exists in the Excel file
    alias = df.loc[0, 'Alias']  # Replace 'Alias' with the actual column name in your Excel file

    # Save the alias to the database
    farmer = Farmer(alias=alias)
    farmer.save()
    print(f"Alias '{alias}' saved successfully.")

except Exception as e:
    print(f"Error: {e}")
