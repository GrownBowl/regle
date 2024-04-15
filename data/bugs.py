import datetime
import sqlalchemy

from .db_session import SqlAlchemyBase
from flask_login import UserMixin


class Bugs(SqlAlchemyBase, UserMixin):
    __tablename__ = 'bugs'

    id = sqlalchemy.Column(sqlalchemy.Integer,
                           primary_key=True, autoincrement=True)
    senders_name = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    date_time = sqlalchemy.Column(sqlalchemy.DateTime,
                                  default=datetime.datetime.now)
    name_bug = sqlalchemy.Column(sqlalchemy.String, nullable=True)
    about_bug = sqlalchemy.Column(sqlalchemy.Text, nullable=True)
