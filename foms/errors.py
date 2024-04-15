from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired


class ErrorsForm(FlaskForm):
    name_bug = StringField('Имя бага', validators=[DataRequired()])
    about_bug = TextAreaField('Опишите баг', validators=[DataRequired()])
    submit = SubmitField('Отправить')
