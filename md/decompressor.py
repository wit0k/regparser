import zipfile
import os.path
from md.settings import *

""" --------------------- Decompression -> Callback functions --------------------- """
def _unzip(FilePath):

    archive = zipfile.ZipFile(FilePath)
    for archive_member in archive.infolist():
        if not archive_member.is_dir():
            with archive.open(archive_member) as archive_item:
                tmp_file = open(f'{FilePath}_{str(archive_member.filename).replace("/", "_")}.tmp', "wb")
                tmp_file.write(archive_item.read())
                tmp_file.close()

    return ERROR_DECOMPRESSOR_DECOMPRESSION_SUCCESS

SUPPORTED_FORMAT = {
    ".ZIP": {"sig": b'\x50\x4b\x03\x04', "siglen": 4, "callback": _unzip},
}

def _is_supported(FilePath):
    if not os.path.isfile(FilePath):
        return ERROR_DECOMPRESSOR_ARCHIVE_NOT_FOUND

    file_extension = os.path.splitext(FilePath)[1].upper()

    try:
        archive_sig, archive_sig_len = SUPPORTED_FORMAT[file_extension]["sig"], SUPPORTED_FORMAT[file_extension]["siglen"]

        with open(FilePath, 'rb') as f:
            file_sig = f.read(archive_sig_len)

        if archive_sig == file_sig:
            return ERROR_DECOMPRESSOR_SUPPORTED_ARCHIVE

    except KeyError:
        return ERROR_DECOMPRESSOR_FORMAT_NOT_SUPPORTED

def supported_archive_extensions():
    extensions = []
    for ext in SUPPORTED_FORMAT:
        extensions.append(ext)

    return extensions

def decompress(FilePath):

    result = _is_supported(FilePath)
    if result == ERROR_DECOMPRESSOR_SUPPORTED_ARCHIVE:
        file_extension = os.path.splitext(FilePath)[1].upper()
        decompress_func = SUPPORTED_FORMAT[file_extension]["callback"]
        decompress_func(FilePath)
    else:
        if result == ERROR_DECOMPRESSOR_ARCHIVE_NOT_FOUND:
            print("ERROR_DECOMPRESSOR_ARCHIVE_NOT_FOUND")
        elif result == ERROR_DECOMPRESSOR_FORMAT_NOT_SUPPORTED:
            print("ERROR_DECOMPRESSOR_FORMAT_NOT_SUPPORTED")

    if result == ERROR_DECOMPRESSOR_DECOMPRESSION_SUCCESS:
        print("ERROR_DECOMPRESSOR_DECOMPRESSION_SUCCESS")