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

dotenv_file = dotenv.find_dotenv()
dotenv.load_dotenv(dotenv_file)

UPLOAD_FOLDER = os.path.join(path_link, "temp_to_upload")
DOWNLOAD_FOLDER = os.path.join(path_link, "temp_to_download")

application = Flask(__name__)

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

login_manager = LoginManager()
login_manager.init_app(application)

convertapi.api_secret = os.getenv("CONVERT_API_SECRET")


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


def send_email(subject, sender, recipients, text_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    mail.send(msg)


def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email('[Regle] Сброс пароля',
               sender="support@regle.ru",
               recipients=[user.email],
               text_body=render_template('reset_password.txt',
                                         user=user, token=token)
               )


@application.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect('/')

    form = RequestResetForm()

    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
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
    if current_user.is_authenticated:
        return redirect('/')

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

        db_sess = db_session.create_session()
        new_pass_user = db_sess.query(User).filter(User.email == email).first()
        new_pass_user.hashed_password = generate_password_hash(form.password.data)
        db_sess.commit()
        return redirect('/login')

    return render_template('reset_password.html', form=form)


@application.route('/admin')
def admin():
    if current_user.role != "Администратор":
        return "У Вас нет доступа к этой странице!"

    db_sess = db_session.create_session()
    bugs = db_sess.query(Bugs).all()

    return render_template('admin_panel.html', bugs=bugs)


@application.route('/admin_edit_roles', methods=["POST", "GET"])
def edit_roles():
    if current_user.role != "Администратор":
        return "У Вас нет доступа к этой странице!"

    db_sess = db_session.create_session()
    users = db_sess.query(User).all()

    if request.method == "POST":
        print(1)
        new_roles = request.form.getlist("new_role")
        user_emails = request.form.getlist("user_email")

        for new_role, user_email in zip(new_roles, user_emails):
            edit_user = db_sess.query(User).filter(User.email == user_email).first()
            edit_user.role = new_role
            db_sess.commit()

        return render_template("edit_roles.html", users=users)

    return render_template("edit_roles.html", users=users)


@application.route('/errors', methods=["POST", "GET"])
def errors_menu():
    form = ErrorsForm()
    if form.validate_on_submit():
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


@application.route('/cloud')
@login_required
def cloud():
    storage = get_storage(os.path.join("users_date", current_user.email))

    return render_template("cloud.html", storage=storage)


@application.route('/convertor/<filename>/<int:from_cloud>', methods=["POST", "GET"])
def convertor(filename, from_cloud):
    file_names = filename.split(";")
    file_sizes = []

    if from_cloud:
        file_sizes.append(human_read_format(os.path.getsize(
            os.path.join("users_date", current_user.email, filename)
        )))

    else:
        for file_name in file_names:
            file_sizes.append(
                human_read_format(os.path.getsize(os.path.join("temp_to_upload", file_name))))

    if request.method == "POST":
        to_convert = request.form.get('to_convert')
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

        if len(file_names) > 1:
            clear_temp_upload()
            return redirect("/cloud")

        else:
            clear_temp_upload()
            return send_from_directory('temp_to_download', f'{get_only_file_name(filename)}.{to_convert}')

    files = zip(file_names, file_sizes)
    return render_template("converter.html", file_names=file_names, formats=convertible,
                           type_file=get_file_extension(file_names[0]), file_sizes=file_sizes, files=files)


@application.route('/convert_from_cloud')
def convert_from_cloud():
    storage = get_storage(os.path.join("users_date", current_user.email))

    return render_template("convert_from_clod.html", storage=storage)


@application.route('/upload', methods=['POST', "GET"])
def upload():
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

        for file_to_upload in request.files.getlist("files"):
            file_name = secure_filename(file_to_upload.filename)

            if allowed_file(file_name):
                file_names.append(file_name)
                file_to_upload.save(os.path.join("temp_to_upload", file_name))

        return redirect(url_for("convertor", filename=";".join(file_names), from_cloud=0))

    return render_template("upload_file.html")


@application.route("/upload_on_cloud", methods=['POST', "GET"])
def upload_on_cloud():
    if request.method == "POST":
        if 'file' not in request.files:
            # После перенаправления на страницу загрузки
            # покажем сообщение пользователю
            return redirect(request.url)
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join("users_date", current_user.email, filename))

            return redirect("/cloud")

    return redirect("/cloud")


@application.route('/download/<filename>')
def download(filename):
    return send_from_directory("temp_to_download", filename)


@application.route("/download_on_cloud/<path:file_name>")
def download_on_cloud(file_name):
    return send_from_directory(os.path.join("users_date", current_user.email), file_name)


@application.route("/delete_file_on_cloud/<path:file_name>")
def delete_file_on_cloud(file_name):
    os.remove(os.path.join("users_date", current_user.email, file_name))
    return redirect("/cloud")


@application.route('/register', methods=['GET', 'POST'])
def reqister():
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
    logout_user()
    return redirect("/")


def main():
    db_session.global_init("db/database.db")
    application.run(debug=True)


if __name__ == '__main__':
    main()
