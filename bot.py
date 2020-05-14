# -*- coding: utf-8 -*-
# Код шифрованя был взят из https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html

import base64
from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Protocol.KDF import PBKDF2
import random
import os
import models
import telebot
from telebot import *
import json
import requests
import string
import random

# apihelper.proxy = {
#         'https': 'socks5h://{}:{}'.format('127.0.0.1','4444')
#     }

commands = [{'command':'start', 'description':'start'}, {'command':'add', 'description':'add new block'}, {'command':'generate_password', 'description':'generate password [lenght]'}, {'command':'all', 'description':'view all you blocks'}, {'command':'help', 'description':'help'}]

folder = os.path.dirname(os.path.abspath(__file__))

cfg = json.loads(open('cfg.txt', 'r').read())

bot = telebot.TeleBot(cfg['token'])
requests.get(f'https://api.telegram.org/bot{cfg["token"]}/setMyCommands?commands={json.dumps(commands)}')

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

# генерация случайного пароля
def random_password(size = 16):
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits + '!$&@*-=+/\\|^:;~`[]{}%()'
    return ''.join(random.choice(chars) for x in range(size))

# создать соль
def get_salt():
    return str(random.randint(100000000000, 999999999999))

# получить хэш пароля
def get_password_hash(password, salt):
    salt = salt.encode()
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key

# зашифровать
def encrypt(raw, password):
    private_key = password
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return bytes.decode(base64.b64encode(iv + cipher.encrypt(raw.encode())))

# расшифровать
def decrypt(enc, password):
    private_key = password
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return bytes.decode(unpad(cipher.decrypt(enc[16:])))

# добавить блок
def add_data(user, data, name, password, login=False):
    salt1 = get_salt()
    hash1 = get_password_hash(password, salt1)
    if login != False:
        login = encrypt(login, hash1)
    data = models.Data.create(user=user, data=encrypt(data, hash1), login=login, name=name, salt=salt1)
    data.save()
    return data

# расшифровать блок
def get_data(data, password):
    salt = data.salt
    enc = decrypt(data.data, get_password_hash(password, salt))
    if str(data.login) != str(False):
        enc1 = decrypt(data.login, get_password_hash(password, salt))
    else:
        enc1 = None
    return (enc, enc1)

def easy_encrypt(text, password, salt):
    hash = get_password_hash(password, salt)
    return encrypt(text, hash)

# добавить/обновить пользвателя
def add_user(id, username = False, firstname = False, lastname = False):
    try:
        user = models.User.get(user_id=id)
        user.username = username or False
        user.firstname = firstname or False
        user.lastname = lastname or False
    except:
        user = models.User.create(user_id = id, username = username or False, firstname = firstname or False, lastname = lastname or False)
    user.save()
    return user

@bot.callback_query_handler(func=lambda call: True)
def callback_inline(call):
    text = call.data
    uid = call.from_user.id
    mid = call.message.message_id
    spl = text.split('_')
    id = int(call.message.json['chat']['id'])
    for i in range(9):
        try:
            spl[i]
        except:
            spl.append('')
    if spl[0] == 'delete-message':
        bot.delete_message(id, int(spl[1])+1)
    elif spl[0] == 'delete':
        models.Data.get(uuid=spl[1]).delete_instance()
        bot.delete_message(id, mid)
    elif spl[0] == 'rename':
        bot.send_message(id, 'Напишите новое название:')
        user = models.User.get(user_id=uid)
        user.action = text
        user.save()
    elif spl[0] == 'reset-pass':
        bot.send_message(id, 'Введите старый пароль от Блока:')
        user = models.User.get(user_id=uid)
        user.action = text
        user.save()
    elif spl[0] == 'reset-data-login':
        bot.send_message(id, 'Введите пароль от Блока:')
        user = models.User.get(user_id=uid)
        user.action = text
        user.save()
    elif spl[0] == 'reset-data-pass':
        bot.send_message(id, 'Введите пароль от Блока:')
        user = models.User.get(user_id=uid)
        user.action = text
        user.save()

@bot.message_handler(commands=['start'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    bot.send_message(id, f"""Привет {user.firstname}, я бот который будет надёжно хранить твои данные в безопасном хранилище!
● Надёжное AES-256 шифрование твоим паролем
● Пароль нигде не хранится (даже хэш), сообщение с ним удаляется
● Полностью открытый <a href="https://github.com/TheAngryPython/SecurePass-TG">исходный код</a>. Ты можешь сам убедиться в нашей честности.

Для того чтобы начать напиши /add""", disable_web_page_preview=True, parse_mode='html')

@bot.message_handler(commands=['help'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    bot.send_message(id, f"""Команды:
/start - старт
/help - помощь
/all - все блоки
/generate_password [длина (16)] - генерироваь сложный пароль

Меня разрабатывает @EgTer. Я написан на python, мой <a href="https://github.com/TheAngryPython/SecurePass-TG">исходный код</a> выдожен на github. Использую шифрование AES-256, хэши паролей не хранятся, а это значит что даже получив доступ к базе данных, НИКТО и НИКОГДА не сможет узнать каким паролем зашифрованы ваши данные""", disable_web_page_preview=True, parse_mode='html')

@bot.message_handler(commands=['generate_password'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    spl = text.split()
    try:
        i = int(spl[1])
        if i > 4096:
            i = 4096
        pas = random_password(i)
    except:
        pas = random_password()
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    bot.send_message(id, f"""{str(pas)}""", disable_web_page_preview=True, parse_mode='html')

@bot.message_handler(commands=['add'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    if len(models.Data.filter(user=user)) >= 50:
        bot.send_message(id, 'Вы превысили лимит в 50 блоков, для его увелечения обратитесь к @EgTer')
    else:
        user.action = 'data_name'
        user.save()
        markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
        cancel = types.KeyboardButton('Остановить')
        markup.row(cancel)
        bot.send_message(id, f"""{user.firstname}, напиши название блока (не шифруется, для вашего удобства). (Помните, что во время создания блока данные хранятся в незашифрованном виде)""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)

@bot.message_handler(commands=['all'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    user.action = 'block_see'
    user.tmp = False
    user.save()
    blocks = models.Data.filter(user=user)
    if len(blocks) != 0:
        markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
        for block in blocks:
            btn = types.KeyboardButton(block.name)
            markup.row(btn)
        bot.send_message(id, f"""Вот твои блоки""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
    else:
        markup = types.ReplyKeyboardRemove()
        bot.send_message(id, f"""У тебя нет блоков. Создать /add""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)

@bot.message_handler(content_types=['text'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    mid = m.message_id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    spl = user.action.split('_')
    try:
        bot.delete_message(id, mid)
        bot.delete_message(id, mid - 1)
    except:
        pass
    for i in range(9):
        try:
            spl[i]
        except:
            spl.append('')
    if text.lower() == 'Остановить'.lower() or text.lower() == 'Stop'.lower():
        user.action = False
        user.tmp = False
        user.save()
        markup = types.ReplyKeyboardRemove()
        bot.send_message(id, f"""Действие прервано""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
    elif user.action == 'data_name':
        try:
            t = True
            models.Data.get(user=user,name=text)
        except:
            t = False
            if text >= 50:
                bot.send_message(id, 'Слишком длинное название!')
            else:
                markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
                cancel = types.KeyboardButton('Остановить')
                no = types.KeyboardButton('Нет')
                markup.row(no, cancel)
                tmp = {'name': text}
                user.tmp = json.dumps(tmp)
                bot.send_message(id, f"""Хорошо, теперь отправь логин (если не требуется нажми "Нет").""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
                user.action = 'data_login'
                user.save()
        if t:
            bot.send_message(id, f"""У вас уже есть блок с таким названием.""", disable_web_page_preview=True, parse_mode='html')
    elif user.action == 'data_login':
        if text >= 100:
            bot.send_message(id, 'Слишком длинный логин')
        else:
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            cancel = types.KeyboardButton('Остановить')
            markup.row(cancel)
            tmp = json.loads(user.tmp)
            if text.lower() == 'Нет'.lower() or text.lower() == 'No'.lower():
                tmp['login'] = False
            else:
                tmp['login'] = text
            user.tmp = json.dumps(tmp)
            bot.send_message(id, f"""Дальше идёт сам блок с данными (пароль, пин-код, кодовое слово).""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
            user.action = 'data_password'
            user.save()
    elif user.action == 'data_password':
        if text >= 3000:
            bot.send_message(id, 'Слишком длинный текст')
        else:
            tmp = json.loads(user.tmp)
            tmp['password'] = text
            user.tmp = json.dumps(tmp)
            bot.send_message(id, f"""Теперь нужен ключ для шифрования всех этих данных.""", disable_web_page_preview=True, parse_mode='html')
            user.action = 'data_key'
            user.save()
    elif user.action == 'data_key':
        tmp = json.loads(user.tmp)
        add_data(user, tmp['password'], tmp['name'], text, login=tmp['login'])
        bot.send_message(id, f"""Блок создан!

Просмореть все блоки: /all""", disable_web_page_preview=True, parse_mode='html')
        user.action = False
        user.save()
    elif user.action == 'block_see':
        try:
            models.Data.get(user=user,name=text)
            user.action = 'block_open'
            user.tmp = text
            user.save()
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            cancel = types.KeyboardButton('Остановить')
            markup.row(cancel)
            bot.send_message(id, f"""Введи пароль от блока""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
        except:
            bot.send_message(id, f"""Такого блока не существует""", disable_web_page_preview=True, parse_mode='html')
    elif user.action == 'block_open':
        try:
            block = models.Data.get(user=user,name=user.tmp)
            data = get_data(block, text)
            if not data[0]:
                markup = types.ReplyKeyboardRemove()
                bot.send_message(id, f"""Неправильный пароль от блока {block.name}""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
            else:
                user.action = False
                user.save()
                keyboard = types.InlineKeyboardMarkup()
                button_1 = types.InlineKeyboardButton(text='Удалить', callback_data=f'1')
                keyboard.add(button_1)
                button_1 = types.InlineKeyboardButton(text='Блок', callback_data=f'delete_{block.uuid}')
                button_2 = types.InlineKeyboardButton(text='Сообщение', callback_data=f'delete-message_{mid}')
                keyboard.add(button_1, button_2)
                button_1 = types.InlineKeyboardButton(text='Переименовать Блок', callback_data=f'rename_{block.uuid}')
                keyboard.add(button_1)
                button_1 = types.InlineKeyboardButton(text='Изменить', callback_data=f'1')
                keyboard.add(button_1)
                button_1 = types.InlineKeyboardButton(text='Пароль', callback_data=f'reset-pass_{block.uuid}')
                button_2 = types.InlineKeyboardButton(text='Логин', callback_data=f'reset-data-login_{block.uuid}')
                keyboard.add(button_1, button_2)
                button_1 = types.InlineKeyboardButton(text='Данные', callback_data=f'reset-data-pass_{block.uuid}')
                keyboard.add(button_1)
                bot.send_message(id, f"""Блок {block.name}
Логин: {data[1]}
Данные: {data[0]}

Удалите это сообщение по завершении.""", disable_web_page_preview=True, parse_mode='html', reply_markup=keyboard)
        except:
            markup = types.ReplyKeyboardRemove()
            bot.send_message(id, f"""Блок не найден!""", disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
    elif spl[0] == 'rename':
        try:
            models.Data.get(name=text)
            bot.send_message(id, 'Блок с таким названием уже есть!')
        except:
            if text >= 50:
                bot.send_message(id, 'Слишком длинное название!')
            else:
                user.action = False
                user.save()
                block = models.Data.get(uuid=spl[1])
                block.name = text
                block.save()
                bot.send_message(id, 'Успешно!')
    elif spl[0] == 'reset-pass':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, 'Неверный пароль!')
        else:
            user.tmp = text
            user.action = 'reset-pass-done_'+spl[1]
            user.save()
            bot.send_message(id, 'Введите новый пароль:')
    elif spl[0] == 'reset-pass-done':
        block = models.Data.get(uuid=spl[1])
        data = get_data(block, user.tmp)
        block.salt = get_salt()
        block.data = easy_encrypt(data[0], text, block.salt)
        block.login = easy_encrypt(str(data[1]), text, block.salt)
        block.save()
        user.tmp = False
        user.action = False
        user.save()
        bot.send_message(id, 'Пароль изменён!')
    elif spl[0] == 'reset-data-login':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, 'Неверный пароль!')
        else:
            if text >= 100:
                bot.send_message(id, 'Слишком длинный логин')
            else:
                user.tmp = text
                user.action = 'reset-data-login-done_'+spl[1]
                user.save()
                bot.send_message(id, 'Введите новый логин:')
    elif spl[0] == 'reset-data-login-done':
        block = models.Data.get(uuid=spl[1])
        block.login = easy_encrypt(text, user.tmp, block.salt)
        block.save()
        user.tmp = False
        user.action = False
        user.save()
        bot.send_message(id, 'Успешно!')
    elif spl[0] == 'reset-data-pass':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, 'Неверный пароль!')
        else:
            if text >= 3000:
                bot.send_message(id, 'Слишком длинный текст')
            else:
                user.tmp = text
                user.action = 'reset-data-pass-done_'+spl[1]
                user.save()
                bot.send_message(id, 'Введите новые данные:')
    elif spl[0] == 'reset-data-pass-done':
        block = models.Data.get(uuid=spl[1])
        block.data = easy_encrypt(text, user.tmp, block.salt)
        block.save()
        user.tmp = False
        user.action = False
        user.save()
        bot.send_message(id, 'Успешно!')

bot.polling(none_stop=True, timeout=123)
