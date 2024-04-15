import os

import convertapi

from flask import Flask, render_template, redirect, request, url_for, send_from_directory, flash, session
from flask_login import LoginManager, login_required, logout_user, login_user, current_user, user_logged_in
from werkzeug.utils import secure_filename

from data.bugs import Bugs
from files_work import *
from foms.errors import ErrorsForm
from foms.user import LoginForm, RegisterForm
from data.users import User
from data import db_session
from config import *

UPLOAD_FOLDER = f"{path_link}\\temp_to_upload"
DOWNLOAD_FOLDER = f"{path_link}\\temp_to_download"

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
login_manager = LoginManager()
login_manager.init_app(app)

convertapi.api_secret = 'zywDTXAK6CL2tPRK'


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


@app.route('/admin')
def admin():
    if current_user.role != "Администратор":
        return "У Вас нет доступа к этой странице!"

    db_sess = db_session.create_session()
    bugs = db_sess.query(Bugs).all()

    return render_template('admin_panel.html', bugs=bugs)


@app.route('/errors', methods=["POST", "GET"])
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


@app.route('/')
def main_menu():  # put application's code here
    return render_template("index.html")


@app.route('/cloud')
@login_required
def cloud():
    storage = get_storage(f"users_date/{current_user.email}")

    return render_template("cloud.html", storage=storage)


@app.route('/convertor/<filename>', methods=["POST", "GET"])
def convertor(filename):
    size = human_read_format(os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], filename)))

    if request.method == "POST":
        to_convert = request.form.get('to_convert')
        convertapi.convert(to_convert, {"File": f"{UPLOAD_FOLDER}\\{filename}"},
                           from_format=get_file_extension(filename)).save_files(DOWNLOAD_FOLDER)

        return send_from_directory(DOWNLOAD_FOLDER, f'{get_only_file_name(filename)}.{to_convert}')

    return render_template("converter.html", filename=filename, formats=convertible,
                           type_file=get_file_extension(filename), file_size=size)


@app.route('/upload', methods=['POST', "GET"])
def upload():
    if request.method == "POST":
        if 'file' not in request.files:
            # После перенаправления на страницу загрузки
            # покажем сообщение пользователю
            return redirect(request.url)
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            return redirect(url_for("convertor", filename=filename))

    return render_template("upload_file.html")


@app.route("/upload_on_cloud", methods=['POST', "GET"])
def upload_on_cloud():
    if request.method == "POST":
        if 'file' not in request.files:
            # После перенаправления на страницу загрузки
            # покажем сообщение пользователю
            return redirect(request.url)
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(f'users_date/{current_user.email}/{filename}')

            return redirect("/cloud")

    return redirect("/cloud")


@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(DOWNLOAD_FOLDER, filename)


@app.route("/download_on_cloud/<path:file_name>")
def download_on_cloud(file_name):
    return send_from_directory(f'users_date/{current_user.email}', file_name)


@app.route("/delete_file_on_cloud/<path:file_name>")
def delete_file_on_cloud(file_name):
    os.remove(f'users_date/{current_user.email}/{file_name}')
    return redirect("/cloud")


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
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
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")

        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)

    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


def main():
    db_session.global_init("db/database.db")
    app.run()


if __name__ == '__main__':
    main()
