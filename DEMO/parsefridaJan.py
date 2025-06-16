import os
import json
import re
from concurrent.futures import ProcessPoolExecutor
import sys


def parse_hooked_method_block(block):
    """Parse a single hooked method block."""
    method_match = re.search(r'@@@Method@@@:(.*?)\n', block)
    method_name = method_match.group(1).strip() if method_match else "UnknownMethod"

    retval_match = re.search(r'@@@ReturnValue@@@(.*?)@@@(.*?)\n', block)
    retval = retval_match.group(1).strip() if retval_match else "UnknownValue"

    stacktrace_match = re.search(r'@@@StackTrace@@@([\s\S]*?)$', block)
    raw_stacktrace = stacktrace_match.group(1).strip() if stacktrace_match else ""
    stacktrace = [line.strip() for line in raw_stacktrace.split("\n") if line.strip()]

    return {
        "retval": retval,
        "function": method_name,
        "stacktrace": stacktrace,
    }


def search_keywords_in_file(file_path):
    """Parse the hooked method data from the given file."""
    results = []
    with open(file_path, "r") as file:
        log_data = file.read()

    blocks = re.findall(r'###HOOKED_METHOD_START###(.*?)###HOOKED_METHOD_END###', log_data, re.DOTALL)
    
    for block in blocks:
        results.append(parse_hooked_method_block(block))
    
    return file_path, results


def process_file(file_path):
    return search_keywords_in_file(file_path)


# def save_results(results, output_file):
#     json_data = []
#     for file_path, result_list in results:
#         for result in result_list:
#             jsonobj = {
#                 "file": os.path.basename(file_path),
#                 "result": result
#             }
#             json_data.append(jsonobj)
def save_results(results, output_file):
    json_data = {}

    # Organize results by file name
    for file_path, result_list in results:
        file_name = os.path.basename(file_path)
        if file_name not in json_data:
            json_data[file_name] = []
        
        # Avoid duplicate dictionaries in the list
        for result in result_list:
            if result not in json_data[file_name]:
                json_data[file_name].append(result)

    # Convert the dictionary to a list of dictionaries for JSON
    json_output = [{"file": key, "results": value} for key, value in json_data.items()]

    with open(output_file, "w") as f:
        json.dump(json_output, f, indent=4)



def main(directory, output_file):
    files = [os.path.join(directory, file) for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]
    
    with ProcessPoolExecutor() as executor:
        futures = [executor.submit(process_file, file) for file in files]
        all_results = []
        for future in futures:
            all_results.append(future.result())
    
    save_results(all_results, output_file)


if __name__ == "__main__":
    apk = sys.argv[1]
    DIRECTORY = f'./results/{apk}/frida'  # Update to your directory path
    OUTPUT_FILE = f'./frida-json-files/{apk}-frida.json'
    
    main(DIRECTORY, OUTPUT_FILE)
