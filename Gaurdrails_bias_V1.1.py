
# Import necessary modules
import os
import re
import sys



# List of keywords to detect possible PII (Personally Identifiable Information) usage
PII_KEYWORDS = [
    'ssn', 'social security', 'dob', 'date of birth', 'passport', 'driver', 'license', 'credit card', 'address', 'phone', 'email', 'name', 'pii'
]

# List of keywords to check for random seed settings (for reproducibility)
SEED_KEYWORDS = ['random.seed', 'np.random.seed', 'torch.manual_seed']

# List of keywords to check for input validation and error handling
VALIDATION_KEYWORDS = ['assert', 'try', 'except', 'if', 'raise', 'ValueError', 'TypeError']

# List of libraries commonly used for explainability and fairness
EXPLAIN_LIBS = ['shap', 'lime', 'fairlearn', 'aif360']

# List of deprecated or unsafe libraries
DEPRECATED_LIBS = ['pickle', 'cPickle', 'marshal']

# List of unsafe functions
UNSAFE_FUNCTIONS = ['eval', 'exec']

# List of model serialization functions (to check for security)
SERIALIZATION_FUNCS = ['pickle.load', 'pickle.loads', 'joblib.load', 'torch.load']



# Function to scan a Python file for guardrails and bias-related keywords

def scan_file(filepath):
    # Read the file content and convert to lowercase for case-insensitive search
    with open(filepath, 'r', encoding='utf-8') as f:
        code = f.read().lower()
        lines = f.readlines()

    results = {}

    # Check for PII-related keywords
    results['pii_found'] = [kw for kw in PII_KEYWORDS if kw in code]

    # Check for random seed usage
    results['seed_found'] = [kw for kw in SEED_KEYWORDS if kw in code]

    # Check for input validation and error handling
    results['validation_found'] = [kw for kw in VALIDATION_KEYWORDS if kw in code]

    # Check for explainability and fairness libraries
    results['explain_libs_found'] = [lib for lib in EXPLAIN_LIBS if lib in code]

    # Check for deprecated/unsafe libraries
    results['deprecated_libs_found'] = [lib for lib in DEPRECATED_LIBS if lib in code]

    # Check for unsafe functions
    results['unsafe_functions_found'] = [func for func in UNSAFE_FUNCTIONS if func in code]

    # Check for insecure model serialization
    results['serialization_found'] = [func for func in SERIALIZATION_FUNCS if func in code]

    # Check for missing docstrings (simple check: look for def/class without triple quotes after)
    with open(filepath, 'r', encoding='utf-8') as f:
        file_lines = f.readlines()
    missing_docstrings = []
    for i, line in enumerate(file_lines):
        line_strip = line.strip()
        if line_strip.startswith('def ') or line_strip.startswith('class '):
            # Look ahead for docstring
            if i+1 < len(file_lines):
                next_line = file_lines[i+1].strip()
                if not (next_line.startswith('"""') or next_line.startswith("''")):
                    missing_docstrings.append(line_strip.split('(')[0])
    results['missing_docstrings'] = missing_docstrings

    return results



# Function to print a summary report of the scan results

def print_report(results, filename):
    print(f'\n--- Guardrails & Bias Check Report for {filename} ---')
    print(f"PII-related keywords found: {results['pii_found']}")
    print(f"Random seed usage found: {results['seed_found']}")
    print(f"Input validation/error handling found: {results['validation_found']}")
    print(f"Explainability/fairness libraries found: {results['explain_libs_found']}")
    print(f"Deprecated/unsafe libraries found: {results['deprecated_libs_found']}")
    print(f"Unsafe functions (eval/exec) found: {results['unsafe_functions_found']}")
    print(f"Insecure model serialization found: {results['serialization_found']}")
    print(f"Functions/classes missing docstrings: {results['missing_docstrings']}")
    print('--- End of Report ---\n')



# Main function to handle command-line arguments and run the scan
def main():
    # Check if the user provided a file path argument
    if len(sys.argv) < 2:
        print('Usage: python guardrails_bias_check.py <file.py>')
        sys.exit(1)
    filepath = sys.argv[1]
    # Check if the file exists
    if not os.path.isfile(filepath):
        print(f'File not found: {filepath}')
        sys.exit(1)
    # Run the scan and print the report
    results = scan_file(filepath)
    print_report(results, filepath)


# Entry point for the script
if __name__ == '__main__':
    main()
