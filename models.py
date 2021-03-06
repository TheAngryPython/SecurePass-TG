# -*- coding: utf8 -*-
# Взято из http://seriyps.ru/blog/2011/06/20/django-orm-standalone/

from peewee import *
import uuid
import datetime

db = SqliteDatabase('db.db')

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    user_id = IntegerField(unique=True)
    username = CharField(default=False)
    firstname = CharField(default=False)
    lastname = CharField(default=False)
    lang = TextField(default='en')
    register_date = DateField(default=datetime.datetime.now)
    uuid = UUIDField(primary_key=True, default=uuid.uuid4)
    action = TextField(default=False)
    tmp = TextField(default=False)

class Data(BaseModel):
    user = ForeignKeyField(User)
    name = TextField()
    data = TextField()
    login = TextField(default=False)
    other = TextField(default=False)
    totp = TextField(default=False)
    uuid = UUIDField(primary_key=True, default=uuid.uuid4)
    creation_date = DateField(default=datetime.datetime.now)
    salt = TextField()

db.connect()
db.create_tables([User, Data])
