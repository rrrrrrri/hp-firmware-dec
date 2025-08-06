"""
Copyright (C) 2025  rrrrrrri

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import re
import zlib
import base64
import hashlib
import logging
import argparse
from Crypto.Cipher import AES
import xml.etree.ElementTree as ET

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

parser = argparse.ArgumentParser(description="HP printer firmware decrypt tool v0.2")
parser.add_argument("-f", "--file", help="Firmware file")
args = parser.parse_args()

def extract_value(data, key):
    pattern = key + r"=([\w\s]+)"
    match = re.search(pattern.encode(), data)
    if match:
        return match.group(1)
    else:
        return None

def decrypt_aes(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

def gen_aes_key(code_name, digest_val):
    data = b"@* WebFWUpdate" + code_name + digest_val
    return hashlib.sha256(data).hexdigest()

class HPFirmware:
    def __init__(self, path):
        self.path = path
        self.raw_data = None

        self.metadata = None
        self.lbi = None
        self.rootfs = None
        self.metadata_path = "./metadata.xml"
        self.lbi_path = "./lbi.bin"
        self.rootfs_path = "./rootfs.bin"

        self.enter_string = b"@PJL ENTER LANGUAGE=FWUPDATE2"
        self.enter_string_index = 0
        self.upgrade_size = 0
        self.metadata_dict = {}

        self.cache_file()
        self.simple_check_file()
        self.split_file()
        self.parse_metadata()
        if not self.check_signature():
            raise "Invalid signature"
        self.decrypt_blob("rootfs_blob")

    def cache_file(self):
        try:
            logging.info("Reading file")
            with open(self.path, "rb") as f:
                self.raw_data = f.read()
        except Exception as e:
            logging.error(f"{e}")
            exit()

    def simple_check_file(self):
        try:
            logging.info("Checking file")
            if self.raw_data[:13] != b"\x1b%-12345X@PJL":
                logging.error("Invalid magic value")
                exit()

            self.enter_string_index = self.raw_data.find(self.enter_string)
            header = self.raw_data[:self.enter_string_index]
            split_header = header.split(b"\n")
            for v in split_header:
                if b"@PJL COMMENT MODEL" in v:
                    logging.debug(f"Model: {extract_value(v, 'MODEL').decode()}")
                elif b"@PJL COMMENT VERSION" in v:
                    logging.debug(f"VERSION: {extract_value(v, 'VERSION').decode()}")
                elif b"@PJL COMMENT DATECODE" in v:
                    logging.debug(f"DATECODE: {extract_value(v, 'DATECODE').decode()}")
                elif b"@PJL UPGRADE SIZE" in v:
                    val = extract_value(v, 'UPGRADE SIZE').decode()
                    logging.debug(f"UPGRADE SIZE: {val}")
                    self.upgrade_size = int(val)
                    assert self.upgrade_size != 0, "Invalid upgrade size"
        except Exception as e:
            logging.error(f"{e}")
            exit()

    def split_file(self):
        try:
            logging.info("Split file")

            logging.debug("Handling metadata")
            metadata_len_index = self.enter_string_index + len(self.enter_string) + 1
            metadata_len = self.raw_data[metadata_len_index :
                                         metadata_len_index + self.raw_data[metadata_len_index:].find(b"\n")]
            self.metadata = self.raw_data[metadata_len_index + len(metadata_len) + 1 :
                                          metadata_len_index + len(metadata_len) + 1 + int(metadata_len, 16)]
            with open(self.metadata_path, "wb") as f:
                f.write(self.metadata)

            logging.debug("Handling LBI_blob")
            lbi_len_index = metadata_len_index + len(metadata_len) + 1 + int(metadata_len, 16)
            lbi_len = self.raw_data[lbi_len_index :
                                    lbi_len_index + self.raw_data[lbi_len_index:].find(b"\n")]
            self.lbi = self.raw_data[lbi_len_index + len(lbi_len) + 1 :
                                          lbi_len_index + len(lbi_len) + 1 + int(lbi_len, 16)]
            with open(self.lbi_path, "wb") as f:
                f.write(self.lbi)

            logging.debug("Handling rootfs_blob")
            rootfs_len_index = lbi_len_index + len(lbi_len) + 1 + int(lbi_len, 16)
            rootfs_len = self.raw_data[rootfs_len_index :
                                       rootfs_len_index + self.raw_data[rootfs_len_index:].find(b"\n")]
            self.rootfs = self.raw_data[rootfs_len_index + len(rootfs_len) + 1 :
                                        rootfs_len_index + len(rootfs_len) + 1 + int(rootfs_len, 16)]
            with open(self.rootfs_path, "wb") as f:
                f.write(self.rootfs)

            del self.raw_data
        except Exception as e:
            logging.error(f"{e}")
            exit()

    def parse_metadata(self):
        try:
            logging.info("Parsing metadata")
            root = ET.fromstring(self.metadata)
            version = root.find("version").text
            assert version == "0.9", "Version check failed"

            logging.debug("XML -> signature")
            signature = root.find("signature")
            self.metadata_dict["signature_template_id"] = signature.find("signature_template_id").text
            self.metadata_dict["public_key_id"] = signature.find("public_key_id").text
            self.metadata_dict["signature_value"] = signature.find("signature_value").text
            self.metadata_dict["digest"] = signature.find("digest").text

            logging.debug("XML -> signedInfo")
            signed_info = root.find("signedInfo")
            self.metadata_dict["update_type"] = signed_info.find("update_type").text
            self.metadata_dict["current_revision"] = signed_info.find("current_revision").text
            self.metadata_dict["updated_revision"] = signed_info.find("updated_revision").text

            logging.debug("XML -> LBI_blob")
            lbi_blob = signed_info.find("LBI_blob")
            self.metadata_dict["LBI_blob"] = {}
            self.metadata_dict["LBI_blob"]["blob_path"] = lbi_blob.find("blob_path").text
            self.metadata_dict["LBI_blob"]["size_compressed"] = lbi_blob.find("size_compressed").text
            self.metadata_dict["LBI_blob"]["size_uncompressed"] = lbi_blob.find("size_uncompressed").text
            self.metadata_dict["LBI_blob"]["blob_digest_compressed"] = lbi_blob.find("blob_digest_compressed").text
            self.metadata_dict["LBI_blob"]["blob_digest_uncompressed"] = lbi_blob.find("blob_digest_uncompressed").text

            logging.debug("XML -> rootfs_blob")
            rootfs_blob = signed_info.find("rootfs_blob")
            self.metadata_dict["rootfs_blob"] = {}
            self.metadata_dict["rootfs_blob"]["blob_path"] = rootfs_blob.find("blob_path").text
            self.metadata_dict["rootfs_blob"]["size_compressed"] = rootfs_blob.find("size_compressed").text
            self.metadata_dict["rootfs_blob"]["size_uncompressed"] = rootfs_blob.find("size_uncompressed").text
            self.metadata_dict["rootfs_blob"]["blob_digest_compressed"] = rootfs_blob.find("blob_digest_compressed").text
            self.metadata_dict["rootfs_blob"]["blob_digest_uncompressed"] = rootfs_blob.find("blob_digest_uncompressed").text

            logging.debug("XML -> Only support LBI_blob + rootfs_blob for now")
            if signed_info.find("recovery_LBI_blob") or \
               signed_info.find("recovery_rootfs_blob") or \
               signed_info.find("rootfs_patch_blob") or \
               signed_info.find("nvm_patch"):
                logging.error("This file is not supported yet")
                exit()

            hash_data = self.metadata_dict.get("update_type") + \
                        self.metadata_dict.get("current_revision") + \
                        self.metadata_dict.get("updated_revision") + \
                        self.metadata_dict.get("LBI_blob").get("blob_path") + \
                        self.metadata_dict.get("LBI_blob").get("size_compressed") + \
                        self.metadata_dict.get("LBI_blob").get("size_uncompressed") + \
                        self.metadata_dict.get("LBI_blob").get("blob_digest_compressed") + \
                        self.metadata_dict.get("LBI_blob").get("blob_digest_uncompressed") + \
                        self.metadata_dict.get("rootfs_blob").get("blob_path") + \
                        self.metadata_dict.get("rootfs_blob").get("size_compressed") + \
                        self.metadata_dict.get("rootfs_blob").get("size_uncompressed") + \
                        self.metadata_dict.get("rootfs_blob").get("blob_digest_compressed") + \
                        self.metadata_dict.get("rootfs_blob").get("blob_digest_uncompressed")

            logging.debug("Checking metadata digest")
            final_hash = hashlib.sha256(hash_data.encode()).hexdigest()
            assert final_hash == base64.b64decode(self.metadata_dict.get("digest")).hex(), "Digest check failed"
        except Exception as e:
            logging.error(f"{e}")
            exit()

    def check_signature(self):
        try:
            logging.debug("Not implemented yet")
            return True
        except Exception as e:
            logging.error(f"{e}")
            exit()

    def decrypt_blob(self, blob_id):
        try:
            logging.info(f"Decrypting {blob_id}")
            blob_obj = self.metadata_dict.get(blob_id)
            assert blob_obj is not None, "Invalid blob"

            enc_data = None
            if blob_id == "LBI_blob":
                enc_data = self.lbi
            elif blob_id == "rootfs_blob":
                enc_data = self.rootfs
            else:
                logging.error("Not implemented yet")
                exit()

            size_compressed = int(blob_obj.get("size_compressed"))
            digest_compressed = base64.b64decode(blob_obj.get("blob_digest_compressed"))
            digest_uncompressed = base64.b64decode(blob_obj.get("blob_digest_uncompressed"))
            logging.debug(f"size_compressed: {size_compressed}")
            logging.debug(f"digest_compressed: {digest_compressed.hex()}")
            logging.debug(f"digest_uncompressed: {digest_uncompressed.hex()}")

            updated_revision = self.metadata_dict.get("updated_revision").lower()
            logging.debug(f"Using code name: {updated_revision[:6]}")

            aes_key = bytes.fromhex(gen_aes_key(updated_revision[:6].encode(), digest_uncompressed))
            logging.debug(f"AES key is: {aes_key[:16].hex()}")

            decrypted = decrypt_aes(enc_data, aes_key[:16], b"\x00" * 16)
            logging.debug(f"Decrypted data checksum: {hashlib.sha256(decrypted[:size_compressed]).hexdigest()}")
            assert hashlib.sha256(decrypted[:size_compressed]).hexdigest() == digest_compressed.hex(), \
                   "Checksum verify failed (compressed)"

            decompressed = zlib.decompress(decrypted, -15)
            logging.debug(f"Uncompressed size: {len(decompressed)}")
            logging.debug(f"Uncompressed data checksum: {hashlib.sha256(decompressed).hexdigest()}")
            assert hashlib.sha256(decompressed).hexdigest() == digest_uncompressed.hex(), \
                   "Checksum verify failed (uncompressed)"

            with open(f"./{blob_id}.fin", "wb") as f:
                f.write(decompressed)

            logging.info(f"Saved to ./{blob_id}.fin")
        except Exception as e:
            logging.error(f"{e}")
            exit()

if __name__ == "__main__":
    if args.file:
        if not os.path.isfile(args.file):
            logging.error("Invalid file")
            exit()

        firmware = HPFirmware(args.file)
    else:
        print("[-] Missing parameters, -h for help")
