import os
from config import *

ALLOWED_EXTENSIONS = set(
    ["ico", "jpeg", "jpg", "bmp", "png", "odt", "doc", "docx", "dwg", "csv", "pdf", "ai", "pps", "ppt", "pptx", "psd",
     "rtf", "svg", "xls", "xlsx"])


class Storage:
    def __init__(self, path: str):
        self.name = path.rsplit("/")[-1]
        self.size = human_read_format(os.path.getsize(path))


def get_storage(path):
    files = []

    for file in os.listdir(path):
        files.append(Storage(f"{path}/{file}"))

    return files


def create_directory(name):
    path = os.path.join(path_link, name)
    os.mkdir(path)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def get_file_extension(filename):
    return filename.rsplit('.', 1)[1]


def get_only_file_name(filename):
    return filename.rsplit('.', 1)[0]


def human_read_format(size):
    count = 0
    format = ["Б", "КБ", "МБ", "ГБ"]

    while size >= 1024:
        size = size / 1024
        count += 1

    return f"{round(size)}{format[count]}"


def check_same_extension(list_files):
    extension = set()

    for file_name in list_files:
        extension.add(get_file_extension(file_name.filename))

    if len(extension) > 1:
        return False

    return True
