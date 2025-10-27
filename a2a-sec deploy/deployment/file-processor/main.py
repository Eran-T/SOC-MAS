import os
import hashlib
import tempfile
import subprocess
from google.cloud import storage
import functions_framework
from cloudevents.http import CloudEvent
import capstone

# Initialize the Google Cloud Storage client
storage_client = storage.Client()

# Get environment variables
BUCKET_UPLOAD_NAME = os.environ.get('BUCKET_UPLOAD_NAME')
BUCKET_DOWNLOAD_NAME = os.environ.get('BUCKET_DOWNLOAD_NAME')

def get_disassembled_content(file_content: bytes) -> str:
    """Disassembles binary code from byte content using the Capstone library."""
    try:
        # Initialize Capstone for x86 64-bit architecture
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        disassembled_lines = []
        # Create a generator for the disassembled instructions.
        instructions = md.disasm(file_content, 0x1000) # 0x1000 is a conventional starting address

        for i in instructions:
            hex_bytes = " ".join([f"{b:02x}" for b in i.bytes])
            line = f"0x{i.address:x}:\t{hex_bytes:<24}\t{i.mnemonic}\t{i.op_str}"
            disassembled_lines.append(line)
        
        if not disassembled_lines:
            return "No valid instructions were disassembled. The file may be packed or not an executable."

        return "\n".join(disassembled_lines)

    except capstone.CsError as e:
        print(f"Capstone disassembly error: {e}")
        return f"Error: Could not disassemble the file. {e}"
        
@functions_framework.cloud_event
def process_file_upload(cloud_event: CloudEvent) -> None:
    """
    Triggered by a CloudEvent from a Cloud Storage bucket.
    This function processes a file uploaded to a Cloud Storage bucket.
    """
    # --- 1. Extract File Information from the CloudEvent ---
    data = cloud_event.data

    file_name = data["name"]
    bucket_name = data["bucket"]

    if bucket_name != BUCKET_UPLOAD_NAME:
        print(f"Ignoring file '{file_name}' from bucket '{bucket_name}'.")
        return

    print(f"Processing file: {file_name} from bucket: {bucket_name}.")
    print(f"validating: \n BUCKET_UPLOAD_NAME: {BUCKET_UPLOAD_NAME}\n BUCKET_DOWNLOAD_NAME: {BUCKET_DOWNLOAD_NAME}")
    # --- 2. Download the File ---
    upload_bucket = storage_client.bucket(bucket_name)
    download_bucket = storage_client.bucket(BUCKET_DOWNLOAD_NAME)
    source_blob = upload_bucket.blob(file_name)

    try:
        file_content = source_blob.download_as_bytes()
        print(f"Successfully downloaded {file_name}.")
    except Exception as e:
        print(f"Error downloading {file_name}: {e}")
        return # Stop execution if download fails

    # --- 3. Save Raw File ---
    raw_file_name = f"{file_name}/raw.txt"
    raw_blob = download_bucket.blob(raw_file_name)
    raw_blob.upload_from_string(file_content)
    print(f"Saved raw file to {raw_file_name} in {BUCKET_DOWNLOAD_NAME}.")

    # --- 4. Process the File: Generate SHA256 ---
    sha256_hash = hashlib.sha256(file_content).hexdigest()
    sha256_file_name = f"{file_name}/hash.txt"
    sha256_blob = download_bucket.blob(sha256_file_name)
    sha256_blob.upload_from_string(sha256_hash)
    print(f"Generated SHA256 and saved to {sha256_file_name} in {BUCKET_DOWNLOAD_NAME}.")

    # --- 5. Process the File: Generate Disassembled Code ---
    try:
        # 1. Disassemble the file content directly using the Capstone function
        disassembled_content = get_disassembled_content(file_content)
        # 2. Upload the disassembled content string to Cloud Storage
        asm_file_name = f"{file_name}/disassembled.txt"
        asm_blob = download_bucket.blob(asm_file_name)
        asm_blob.upload_from_string(disassembled_content)
        print(f"Generated disassembled file and saved to {asm_file_name} in {BUCKET_DOWNLOAD_NAME}.")

    except FileNotFoundError:
        print("Error: 'objdump' command not found. Ensure binutils is installed in the function environment.")
    except subprocess.CalledProcessError as e:
        print(f"Error during disassembly with objdump. The file may not be a valid executable. Error: {e}")
        print(f"Stderr: {e.stderr}")
    except Exception as e:
        print(f"An unexpected error occurred during disassembly: {e}")


    # --- 6. Delete the Original File from the Upload Bucket ---
    try:
        source_blob.delete()
        print(f"Successfully deleted {file_name} from {bucket_name}.")
    except Exception as e:
        print(f"Error deleting {file_name} from {bucket_name}: {e}")

    print("File processing complete.")

