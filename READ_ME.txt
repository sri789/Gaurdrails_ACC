PS C:\Users\DELL> & "C:/Program Files/Python312/python.exe" c:/Users/DELL/Downloads/Gaurdrails_bias.py C:\Users\DELL\Downloads\Corpus\Supervised_Learning.py

--- Guardrails & Bias Check Report for C:\Users\DELL\Downloads\Corpus\Supervised_Learning.py ---
PII-related keywords found: ['name']
Random seed usage found: []
Input validation/error handling found: ['if']
Explainability/fairness libraries found: []
--- End of Report ---

PS C:\Users\DELL>



Your script is working as intended! It scanned your Supervised_Learning.py file and reported:

PII-related keywords found: ['name']
Random seed usage found: [] (none found)
Input validation/error handling found: ['if']
Explainability/fairness libraries found: [] (none found)
This means:

The script detected the word "name" (which could be a PII indicator).
No random seed setting was found (consider adding one for reproducibility).
The script found at least one if statement (basic input validation or logic).


Version 2 :
The script now includes advanced checks for:

Deprecated/unsafe libraries (e.g., pickle, marshal)
Use of unsafe functions (eval, exec)
Insecure model serialization usage
Functions/classes missing docstrings (code quality)

No explainability or fairness libraries were detected.
