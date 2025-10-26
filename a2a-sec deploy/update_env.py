import sys
from pathlib import Path
from dotenv import load_dotenv, set_key

def write_to_env(key, value):
    """
    Finds the .env file in the current or parent directories and
    writes a key-value pair to it.
    """
    # Start searching for .env from the current directory upwards
    # This makes the script location-independent
    env_path = Path('.env')
    #print(f"[DEBUG]\nenv var key name: {key}\nenv var value: {value}")
    # Set the key-value pair. set_key will create the file if it doesn't exist,
    # but the main script checks for it anyway.
    # It also correctly quotes values.
    set_key(dotenv_path=env_path, key_to_set=key, value_to_set=value)
    print(f"Updated '{key}' in {env_path.resolve()}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 update_env.py <KEY> <VALUE>")
        sys.exit(1)
    
    key_to_update = sys.argv[1]
    value_to_update = sys.argv[2]
    write_to_env(key_to_update, value_to_update)
