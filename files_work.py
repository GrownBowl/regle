import os
import shutil

ALLOWED_EXTENSIONS = set(
    ["ico", "jpeg", "jpg", "bmp", "png", "odt", "doc", "docx", "dwg", "csv", "pdf", "ai", "pps", "ppt", "pptx", "psd",
     "rtf", "svg", "xls", "xlsx"])  # Допустимые расширения файлов


class Storage:
    """Класс описывающий облачное хранилище"""
    def __init__(self, path: str):
        self.name = path.rsplit("/")[-1]
        self.size = human_read_format(os.path.getsize(path))


def get_storage(path):
    """
    Функция получения файлов по пути
    :param path: путь к папке
    :return: список файлов
    """

    files = []

    for file in os.listdir(path):
        files.append(Storage(f"{path}/{file}"))

    return files


def create_directory(name):
    """
    Функция создающая папку пользователя для облачного хранилища
    :param name: Имя папка
    """

    path = os.path.join('users_date', name)
    os.mkdir(path)


def allowed_file(filename):
    """
    Функция проверки файла на корректонсть расширения
    :param filename: Полное имя файла
    :return: Bool
    """

    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


def get_file_extension(filename):
    """
    Функция получения только расширения файла
    :param filename: Имя файла
    :return: Расширение файла
    """

    return filename.rsplit('.', 1)[1]


def get_only_file_name(filename):
    """
    Функция получения только имени файла, без расширения
    :param filename: Имя файла
    :return: Имя файла, без расширения
    """

    return filename.rsplit('.', 1)[0]


def human_read_format(size):
    """
    Функция получения человеко-читаемого формата размера файла
    :param size: Размер файла в байтах
    :return: Размер файла
    """

    count = 0
    format = ["Б", "КБ", "МБ", "ГБ"]

    while size >= 1024:
        size = size / 1024
        count += 1

    return f"{round(size)}{format[count]}"


def check_same_extension(list_files):
    """
    Функция проверяющая список файлов на однотипность расширения
    :param list_files: Список файлов
    :return: Bool
    """
    extension = set()

    for file_name in list_files:
        extension.add(get_file_extension(file_name.filename))

    if len(extension) > 1:
        return False

    return True


def clear_temp_upload():
    """Функция очистки папки temp_to_upload"""

    shutil.rmtree('temp_to_upload')
    os.mkdir('temp_to_upload')