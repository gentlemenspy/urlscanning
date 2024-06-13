import hashlib

def run(file_path):
    def compute_md5(file_path):
        md5_hash = hashlib.md5()
        try:
            with open(file_path, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except FileNotFoundError:
            return "File not found."
        except Exception as e:
            return f"An error occurred: {str(e)}"

    md5_result = compute_md5(file_path)
    print(f"MD5 hash of the file: {md5_result}")
