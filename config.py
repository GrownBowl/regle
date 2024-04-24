path_link = "C:\\Users\\children\\Desktop\\regle"

convertible = {
    "ico": ["png", "svg", "jpg"],
    "jpeg": ["jpg", "png", "svg", "pdf"],
    "jpg": ["png", "svg", "pdf"],
    "bmp": ["jpg", "pdf", "png", "svg"],
    "png": ["jpg", "pdf", "svg"],
    "odt": ["doc", "docx", "pdf", "txt"],
    "doc": ["odt", "rtf", "txt", "docx"],
    "docx": ["odt", "pdf", "png", "rtf", "txt"],
    "dwg": ["pdf"],
    "csv": ["pdf", "xlsx"],
    "pdf": ["docx", "pptx", "xlsx", "xls"],
    "ai": ["jpg", "png", "svg"],
    "pps": ["pdf", "pptx"],
    "ppt": ["pdf", "pptx"],
    "pptx": ["pdf"],
    "psd": ["jpg", "png", "svg"],
    "rtf": ["docx", "odt", "pdf", "txt"],
    "svg": ["jpg", "png"],
    "xls": ["xlsx", "csv"],
    "xlsx": ["csv", "pdf", "xls", ],
}


def check_password(password: str) -> bool:
    count_digits = 0
    count_uppers = 0
    count_lowers = 0
    count_special_symbols = 0

    special_symbols = ['~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '`', '-', '=']

    if len(password) < 8:
        return False

    for num in password:
        if num in special_symbols:
            count_special_symbols += 1

        if num.isdigit():
            count_digits += 1

        if num.islower():
            count_lowers += 1

        if num.isupper():
            count_uppers += 1

    if count_uppers < 1 or count_lowers < 1 or count_special_symbols < 1:
        return False

    if count_digits < 1:
        return False

    return True
