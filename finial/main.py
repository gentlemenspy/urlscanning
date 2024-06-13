import sys

def display_menu():
    print("""
    1. Scan URL 
    2. Scan domain
    3. Scan file
    4. Exit
    """)

def get_choice():
    return input("Enter your choice: ")

def run_module(module_name, *args):
    try:
        module = __import__(module_name)
        if hasattr(module, 'run'):
            module.run(*args)
        else:
            print(f"Error: {module_name} module does not have a 'run' function.")
    except ImportError:
        print(f"Error: Could not import {module_name} module.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    api_key = 'ad404788720b87bc5a826648b0321313c92c8109e3e527a4ed4b5e92ec13a077'
    
    while True:
        display_menu()
        choice = get_choice()
        
        if choice == "1":
            url = input("Enter the URL: ")
            run_module('urlscan', api_key, url)
        elif choice == "2":
            domain = input("Enter the domain: ")
            run_module('domain', api_key, domain)
        elif choice == "3":
            file_path = input("Enter the file path: ")
            run_module('file', file_path)
        elif choice == "4":
            sys.exit()
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
