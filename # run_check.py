# run_check.py
import sys
sys.path.insert(0, r'C:\Users\DELL\Downloads')
import json
from Gaurdrails_bias import scan_file, print_report

target = 'C:\\Users\\DELL\\Downloads\\Corpus\\Supervised_Learning.py'
results = scan_file(target)

# Print human report
print_report(results, target)

# Or get JSON for programmatic consumption
print(json.dumps(results, indent=2))