import hashlib
import os
import shutil

from volatilitybot.conf.config import STORE_PATH


def generate_file_sha256(file_path, blocksize=2 ** 20):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            buf = f.read(blocksize)
            if not buf:
                break
            hasher.update(buf)

    return hasher.hexdigest()


def copy_to_store(file_path,file_sha256):
    new_dir = os.path.join(STORE_PATH,file_sha256)
    try:
        os.makedirs(new_dir)
    except FileExistsError:
        # If directory already exists, it is fine...
        pass

    target_path = os.path.join(new_dir,'{}.bin'.format(file_sha256))
    shutil.copy(file_path,target_path)
    return target_path
