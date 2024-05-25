import os
import dotenv

import convertapi

from flask import Flask, render_template, redirect, request, url_for, send_from_directory
from flask_login import LoginManager, login_required, logout_user, login_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from data.bugs import Bugs
from files_work import *
from foms.errors import ErrorsForm
from foms.user import LoginForm, RegisterForm, ResetPasswordForm, RequestResetForm
from data.users import User
from data import db_session
from config import *

# Загрузка данных из файла окружения
dotenv_file = dotenv.find_dotenv()
dotenv.load_dotenv(dotenv_file)

UPLOAD_FOLDER = os.path.join(path_link, "temp_to_upload")
DOWNLOAD_FOLDER = os.path.join(path_link, "temp_to_download")

application = Flask(__name__)

# Добавление информации о почтовом сервисе
application.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD")
)

mail = Mail(application)

application.config['SECRET_KEY'] = os.getenv("FLASK_API_SECRET")
application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Создание логин менеджера
login_manager = LoginManager()
login_manager.init_app(application)

convertapi.api_secret = os.getenv("CONVERT_API_SECRET")


@login_manager.user_loader
def load_user(user_id: int) -> User:
    """Функция загрузки пользователя"""

    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


def send_email(subject, sender, recipients, text_body):
    """
    Функция отправки сообщения на почту
    :param subject: Заголовок сообщения
    :param sender: Отправитель сообщения
    :param recipients: Получатель сообщения
    :param text_body: Текст сообщения
    """

    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    mail.send(msg)


def send_password_reset_email(user):
    """
    Функция отправки пользователю письма с ссылкой на восстановление пароля
    :param user: пользователь, которому необходимо отправить сообщение
    """
    token = user.get_reset_password_token()
    send_email('[Regle] Сброс пароля',
               sender="support@regle.ru",
               recipients=[user.email],
               text_body=render_template('reset_password.txt',
                                         user=user, token=token)
               )


@application.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    """ Функция обработчик странички с запросом на смену пароля"""
    if current_user.is_authenticated:
        return redirect('/')

    form = RequestResetForm()

    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()

        # Если пользователь существует,
        # то ему отправляется сообщение на почту с ссылкой на восстановление пароля
        if user:
            send_password_reset_email(user)

        else:
            return render_template('request_reset_password.html',
                                   title='Сброс пароля', form=form, message="Проверьте правильность почты!")
        return redirect(url_for('login'))

    return render_template('request_reset_password.html',
                           title='Сброс пароля', form=form)


@application.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Функция обработчик страники со сменой пароля
    :param token:  Временный токен  пользователя
    """

    if current_user.is_authenticated:
        return redirect('/')

    # Проверка действительности  токена
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect('/')

    email = user.email

    form = ResetPasswordForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('reset_password.html',
                                   form=form,
                                   message="Пароли не совпадают")

        if not check_password(form.password.data):
            return render_template('reset_password.html', form=form,
                                   message="Пароль должен быть не менее 8 симвловол и содержать минимум одну букву в "
                                           "верхнем регистре, одну цифру и один специальный символ")

        # Смена пароля в базе данных
        db_sess = db_session.create_session()
        new_pass_user = db_sess.query(User).filter(User.email == email).first()
        new_pass_user.hashed_password = generate_password_hash(form.password.data)
        db_sess.commit()
        return redirect('/login')

    return render_template('reset_password.html', form=form)


@application.route('/admin')
def admin():
    """Функция обработчик страницы с админ-панелью"""

    # Проверка, что у пользователя есть роль Администратора
    if current_user.role != "Администратор":
        return "У Вас нет доступа к этой странице!"

    db_sess = db_session.create_session()
    bugs = db_sess.query(Bugs).all()

    return render_template('admin_panel.html', bugs=bugs)


@application.route('/admin_edit_roles', methods=["POST", "GET"])
def edit_roles():
    """Функция обработчик страницы с редактированием ролей пользователей"""

    if current_user.role != "Администратор":
        return "У Вас нет доступа к этой странице!"

    db_sess = db_session.create_session()
    users = db_sess.query(User).all()

    if request.method == "POST":
        # Получаем из формы выбранные роли и почты пользователей
        new_roles = request.form.getlist("new_role")
        user_emails = request.form.getlist("user_email")

        # Редактируем в базе данных роли пользователям
        for new_role, user_email in zip(new_roles, user_emails):
            edit_user = db_sess.query(User).filter(User.email == user_email).first()
            edit_user.role = new_role
            db_sess.commit()

        return render_template("edit_roles.html", users=users)

    return render_template("edit_roles.html", users=users)


@application.route('/errors', methods=["POST", "GET"])
def errors_menu():
    """Функция обработчик формы сообщения о багаз"""

    form = ErrorsForm()
    if form.validate_on_submit():
        # Если пользователь нажал отправить,
        # то записываем информацию о багах в базу данных
        db_sess = db_session.create_session()
        error = Bugs(
            senders_name=current_user.name,
            name_bug=form.name_bug.data,
            about_bug=form.about_bug.data
        )
        db_sess.add(error)
        db_sess.commit()
        return redirect('/')
    return render_template('errors.html', form=form)


@application.route('/')
@application.route('/index')
def main_menu():  # put application's code here
    return render_template("index.html")


@application.route('/computer_device')
def computer_device():
    return render_template('computer_device.html')


@application.route('/cloud')
@login_required
def cloud():
    """Функция обработчик страницы с облачным хранилищем"""
    # Получаем все файлы пользователя
    storage = get_storage(os.path.join("users_date", current_user.email))

    return render_template("cloud.html", storage=storage)


@application.route('/convertor/<filename>/<int:from_cloud>', methods=["POST", "GET"])
def convertor(filename, from_cloud):
    """
    Функция обработчик страницы с конвертированием файлов
    :param filename: Имя файла
    :param from_cloud: Файл загружен из хранилища или с компьютера
    """

    file_names = filename.split(";")
    file_sizes = []

    if from_cloud:
        # Если файл загружен из хранилища, получаем его размер
        file_sizes.append(human_read_format(os.path.getsize(
            os.path.join("users_date", current_user.email, filename)
        )))

    else:
        # Если файл загружен с компьютера, получем его размер
        for file_name in file_names:
            file_sizes.append(
                human_read_format(os.path.getsize(os.path.join("temp_to_upload", file_name))))

    if request.method == "POST":
        # Полчаем расширение в которое необходимо конвертировать файл
        to_convert = request.form.get('to_convert')

        # Конвертируем файлы
        if from_cloud:
            convertapi.convert(to_convert, {"File": os.path.join("users_date", current_user.email, filename)},
                               from_format=get_file_extension(filename)).save_files("temp_to_download")
        else:
            for name in file_names:
                if len(file_names) > 1:
                    convertapi.convert(to_convert, {"File": os.path.join("temp_to_upload", name)},
                                       from_format=get_file_extension(name)).save_files(
                        os.path.join("users_date", current_user.email))
                else:
                    convertapi.convert(to_convert, {"File": os.path.join("temp_to_upload", name)},
                                       from_format=get_file_extension(name)).save_files("temp_to_download")

        # Если количество файлов больше одного, то переадресовываем пользователя на страницу хранилища
        if len(file_names) > 1:
            # Очищаем папку temp_to_upload
            clear_temp_upload()
            return redirect("/cloud")

        else:
            # Очищаем папку temp_to_upload
            clear_temp_upload()
            return send_from_directory('temp_to_download', f'{get_only_file_name(filename)}.{to_convert}')

    files = zip(file_names, file_sizes)
    return render_template("converter.html", file_names=file_names, formats=convertible,
                           type_file=get_file_extension(file_names[0]), file_sizes=file_sizes, files=files)


@application.route('/convert_from_cloud')
def convert_from_cloud():
    """Функция обработчик страницы с выбором файла для конвертации из хранилища"""

    storage = get_storage(os.path.join("users_date", current_user.email))

    return render_template("convert_from_clod.html", storage=storage)


@application.route('/upload', methods=['POST', "GET"])
def upload():
    """Функция обработчик страницы с загрузкой файлов для конвертации"""

    if request.method == "POST":
        if not request.files:
            return redirect(request.url)

        file_names = []

        if len(request.files.getlist("files")) > 1 and not current_user.is_authenticated:
            return render_template("upload_file.html", message="Необходимо загрузить один файл!")

        if len(request.files.getlist("files")) > 5:
            return render_template("upload_file.html", message='Необходимо загружать не более 5 файлов!')

        if not check_same_extension(request.files.getlist("files")):
            return render_template("upload_file.html", message='Необходимо загружать файлы одного расширения!')

        # Сохраняем файлы
        for file_to_upload in request.files.getlist("files"):
            file_name = secure_filename(file_to_upload.filename)

            if allowed_file(file_name):
                file_names.append(file_name)
                file_to_upload.save(os.path.join("temp_to_upload", file_name))

        return redirect(url_for("convertor", filename=";".join(file_names), from_cloud=0))

    return render_template("upload_file.html")


@application.route("/upload_on_cloud", methods=['POST', "GET"])
def upload_on_cloud():
    """Функия обработчки загрузки файлов в хранилище"""

    if request.method == "POST":
        if 'file' not in request.files:
            # После перенаправления на страницу загрузки
            # покажем сообщение пользователю
            return redirect(request.url)
        file = request.files['file']

        # Сохраняем файл
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join("users_date", current_user.email, filename))

            return redirect("/cloud")

    return redirect("/cloud")


@application.route('/download/<filename>')
def download(filename):
    """
    Функция обработчик странички со скачиванием файла
    :param filename: Имя файла
    """

    return send_from_directory("temp_to_download", filename)


@application.route("/download_on_cloud/<path:file_name>")
def download_on_cloud(file_name):
    """
    Функция обработчкич страницы со скачиванием файла с хранилища
    :param file_name:
    """

    return send_from_directory(os.path.join("users_date", current_user.email), file_name)


@application.route("/delete_file_on_cloud/<path:file_name>")
def delete_file_on_cloud(file_name):
    """
    Функция обработчик страницы с удалением файла из хранилища
    :param file_name: Имя файлв
    """

    os.remove(os.path.join("users_date", current_user.email, file_name))
    return redirect("/cloud")


@application.route('/register', methods=['GET', 'POST'])
def reqister():
    """Функция обработчик с формой регистрации пользователя"""

    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")

        if not check_password(form.password.data):
            return render_template('register.html', title='Регистрация', form=form,
                                   message="Пароль должен быть не менее 8 симвловол и содержать минимум одну букву в "
                                           "верхнем регистре, одну цифру и один специальный символ")

        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(
            name=form.name.data,
            email=form.email.data,
            role="Участник"
        )
        user.set_password(form.password.data)
        db_sess.add(user)
        db_sess.commit()
        create_directory(form.email.data)
        return redirect(url_for('login'))

    return render_template('register.html', title='Регистрация', form=form)


@application.route('/login', methods=['GET', 'POST'])
def login():
    """Фнукция обработчик страницы с авторизацией пользователя"""

    form = LoginForm()

    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/index")

        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)

    return render_template('login.html', title='Авторизация', form=form)


@application.route('/logout')
@login_required
def logout():
    """Функция обработчик страницы с выходом пользователя из личного кабинета"""

    logout_user()
    return redirect("/")


def main():
    db_session.global_init("db/database.db")
    application.run(debug=True)


if __name__ == '__main__':
    main()
