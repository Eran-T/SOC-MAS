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

import re
import struct

def extract_strings(data: bytes, min_length: int = 4) -> str:
    """Helper to find ASCII strings in the raw bytes."""
    # Find sequences of printable characters
    pattern = rb"[ -~]{" + str(min_length).encode() + rb",}"
    found = []
    for match in re.finditer(pattern, data):
        # Decode bytes to string
        s = match.group().decode("ascii", errors="ignore")
        found.append(f"Offset 0x{match.start():x}: {s}")
    
    if not found: return "No readable strings found."
    # Limit output to 20 lines to keep it clean
    return "\n".join(found[:30])

def analyze_binary(file_content: bytes) -> str:
    output = []
    
    # --- 1. STRING EXTRACTION (The missing part) ---
    output.append("--- 1. Readable Strings (Data Section) ---")
    output.append(extract_strings(file_content))
    output.append("-" * 40)

    # --- 2. ARCHITECTURE DETECTION ---
    arch = capstone.CS_ARCH_X86
    mode = capstone.CS_MODE_64
    arch_name = "x86_64 (Default)"
    
    # Check for Mach-O Magic Number (0xfeedfacf)
    if file_content.startswith(b'\xcf\xfa\xed\xfe'):
        cpu_type = struct.unpack('<I', file_content[4:8])[0]
        if cpu_type == 16777228: # ARM64
            arch = capstone.CS_ARCH_ARM64
            mode = capstone.CS_MODE_ARM
            arch_name = "ARM64 (Apple Silicon)"
        elif cpu_type == 16777223: # x86_64
            arch_name = "x86_64 (Intel)"
            
    output.append(f"\n--- 2. Code Analysis ({arch_name}) ---")

    # --- 3. FIND CODE ENTRY POINT ---
    code_offset = 0
    entry_method = "Header Lookup"
    
    # Try to find the '__text' section definition in the headers
    match = re.search(b'__text\x00', file_content)
    if match:
        # Jump to where the "offset" integer is stored in the section header
        # In Mach-O 64, offset is 48 bytes after the name start
        offset_ptr = match.start() + 48
        if offset_ptr + 4 < len(file_content):
            code_offset = struct.unpack('<I', file_content[offset_ptr:offset_ptr+4])[0]
    
    # Fallback: If header lookup failed (offset is 0), scan for signatures
    if code_offset == 0:
        entry_method = "Signature Scan"
        if arch == capstone.CS_ARCH_ARM64:
            # Look for ARM64 function start (stp x29, x30...)
            pos = file_content.find(b'\xfd\x7b') 
            code_offset = pos if pos != -1 else 0x1000
        else:
            # Look for x86 function start (push rbp; mov rbp, rsp)
            pos = file_content.find(b'\x55\x48\x89\xe5')
            code_offset = pos if pos != -1 else 0x1000

    output.append(f"Disassembling at Offset: 0x{code_offset:x} (Method: {entry_method})")

    # --- 4. DISASSEMBLE ---
    try:
        md = capstone.Cs(arch, mode)
        md.skipdata = True # Don't crash on data bytes
        
        # Grab a chunk of code at the calculated offset
        # We limit to 200 bytes to prevent flooding the screen
        code_chunk = file_content[code_offset : code_offset + 200]
        instructions = md.disasm(code_chunk, code_offset)
        
        output.append("\n--- Instructions ---")
        count = 0
        for i in instructions:
            hex_bytes = " ".join([f"{b:02x}" for b in i.bytes])
            # Formatting: Address | Hex | Mnemonic | Operands
            line = f"0x{i.address:x}:\t{hex_bytes:<20}\t{i.mnemonic}\t{i.op_str}"
            output.append(line)
            count += 1
            
        if count == 0:
            output.append("No instructions decoded. The file might be encrypted or compressed.")

    except Exception as e:
        output.append(f"Disassembly Error: {e}")

    return "\n".join(output)
        
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
        disassembled_content = analyze_binary(file_content)
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

