import os

# Base folder is where this script lives
base_dir = os.path.dirname(os.path.abspath(__file__))

# Folders to create
folders = [
    "mcp_core",
    "attack",
    "evil_mcp",
]

# Files to create (path, content)
files = {
    "mcp_core/__init__.py": "",
    "mcp_core/base_client.py": "",
    "requirements.txt": "fastmcp\n",
}

# Create folders
for folder in folders:
    path = os.path.join(base_dir, folder)
    os.makedirs(path, exist_ok=True)
    print(f"[+] Created folder: {folder}/")

# Create files
for file_path, content in files.items():
    path = os.path.join(base_dir, file_path)
    with open(path, "w") as f:
        f.write(content)
    print(f"[+] Created file: {file_path}")

print("\nDone. Folder structure is ready.")
