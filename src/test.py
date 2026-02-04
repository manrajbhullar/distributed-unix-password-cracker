import crypt
import os

def generate_shadow_file():
    username = "manraj"
    password = "az1"
    filename = "shadow"

    # Algorithm IDs required: yescrypt, bcrypt, SHA256, SHA512, MD5
    algs = {
        "yescrypt": "$y$j9T$saltsaltsalt",
        "bcrypt":   "$2b$12$saltsaltsaltsaltsaltse",
        "sha256":   "$5$saltsalt",
        "sha512":   "$6$saltsalt",
        "md5":      "$1$saltsalt"
    }

    try:
        with open(filename, "w") as f:
            for name, salt_prefix in algs.items():
                try:
                    hash_val = crypt.crypt(password, salt_prefix)
                    # user:hash:last_change:min:max:warn:inactive:expire:reserved
                    entry = f"{username}_{name}:{hash_val}:19000:0:99999:7:::\n"
                    f.write(entry)
                    print(f"Added {name}")
                except Exception as e:
                    print(f"Skipped {name}: {e}")
        print(f"\nCreated '{filename}' in {os.getcwd()}")
    except Exception as e:
        print(f"Error writing file: {e}")


if __name__ == "__main__":
    generate_shadow_file()