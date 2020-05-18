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
import pyotp

# apihelper.proxy = {
#         'https': 'socks5h://{}:{}'.format('127.0.0.1','4444')
#     }

commands = [{'command':'start', 'description':'start'}, {'command':'settings', 'description':'settings'}, {'command':'add', 'description':'add new block'}, {'command':'generate_password', 'description':'generate password [lenght]'}, {'command':'all', 'description':'view all you blocks'}, {'command':'help', 'description':'help'}]

folder = os.path.dirname(os.path.abspath(__file__))

answers = json.loads(open('answers.txt', 'r').read())
try:
    cfg = json.loads(open('cfg.txt', 'r').read())
    print('Config found, using config settings')
except:
    cfg = {'token':os.environ['TOKEN'],'id':int(os.environ['ADMIN'])}
    print('Config not found, using heroku settings')

bot = telebot.TeleBot(cfg['token'])
requests.get(f'https://api.telegram.org/bot{cfg["token"]}/setMyCommands?commands={json.dumps(commands)}')

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

langs = ['ru', 'en', 'it', 'fr', 'de', 'uk', 'pl']

# получить текст сообщения
def ga(name, lang='en'):
    return answers[name][lang]

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
def add_data(user, data, name, password, login=False, other=False, totp=False):
    salt1 = get_salt()
    hash1 = get_password_hash(password, salt1)
    if login != False:
        login = encrypt(login, hash1)
    if other != False:
        other = encrypt(other, hash1)
    if totp != False:
        totp = encrypt(totp, hash1)
    data = models.Data.create(user=user, data=encrypt(data, hash1), login=login, name=name, salt=salt1, other=other, totp=totp)
    data.save()
    return data

# расшифровать блок
def get_data(data, password):
    salt = data.salt
    hash = get_password_hash(password, salt)
    enc = decrypt(data.data, hash)
    if str(data.login) != str(False):
        enc1 = decrypt(data.login, hash)
    else:
        enc1 = None
    if str(data.other) != str(False):
        enc2 = decrypt(data.other, hash)
    else:
        enc2 = None
    if str(data.totp) != str(False):
        enc3 = decrypt(data.totp, hash)
    else:
        enc3 = None
    return (enc, enc1, enc2, enc3)

def easy_encrypt(text, password, salt):
    hash = get_password_hash(password, salt)
    return encrypt(text, hash)

# добавить/обновить пользвателя
def add_user(id, username = False, firstname = False, lastname = False, lang = False):
    try:
        user = models.User.get(user_id=id)
        if username:
            user.username = username or False
        if firstname:
            user.firstname = firstname or False
        if lastname:
            user.lastname = lastname or False
    except:
        user = models.User.create(user_id = id, username = username or False, firstname = firstname or False, lastname = lastname or False, lang = lang or 'en')
    user.save()
    return user

def return_settings(block, user):
    keyboard = types.InlineKeyboardMarkup()
    button_1 = types.InlineKeyboardButton(text=ga('delete', user.lang), callback_data=f'1')
    keyboard.add(button_1)
    button_1 = types.InlineKeyboardButton(text=ga('block', user.lang), callback_data=f'delete_{block.uuid}')
    button_2 = types.InlineKeyboardButton(text=ga('msg', user.lang), callback_data=f'delete-message')
    keyboard.add(button_1, button_2)
    button_1 = types.InlineKeyboardButton(text=ga('re_bl', user.lang), callback_data=f'rename_{block.uuid}')
    keyboard.add(button_1)
    button_1 = types.InlineKeyboardButton(text=ga('ch', user.lang), callback_data=f'1')
    keyboard.add(button_1)
    button_1 = types.InlineKeyboardButton(text=ga('pas', user.lang), callback_data=f'reset-pass_{block.uuid}')
    button_2 = types.InlineKeyboardButton(text=ga('log', user.lang), callback_data=f'reset-data-login_{block.uuid}')
    keyboard.add(button_1, button_2)
    button_1 = types.InlineKeyboardButton(text=ga('dt', user.lang), callback_data=f'reset-data-pass_{block.uuid}')
    button_2 = types.InlineKeyboardButton(text=ga('nt', user.lang), callback_data=f'reset-data-note_{block.uuid}')
    keyboard.add(button_1, button_2)
    button_1 = types.InlineKeyboardButton(text='2FA', callback_data=f'reset-data-totp_{block.uuid}')
    keyboard.add(button_1)
    button_1 = types.InlineKeyboardButton(text=ga('upd', user.lang), callback_data=f'update-block-msg_{block.uuid}')
    keyboard.add(button_1)
    button_1 = types.InlineKeyboardButton(text=ga('share', user.lang), switch_inline_query=f'{block.uuid}')
    keyboard.add(button_1)
    return keyboard

def return_block_text(block, data, user):
    totp = data[3]
    if totp:
        try:
            totp = pyotp.TOTP(totp).now()
        except:
            totp = 'error'
    return ga('ret_bl_txt', user.lang).format(**locals())

def return_block_text_enc(block, user):
    return ga('ret_bl_txt_e', user.lang).format(**locals())

@bot.inline_handler(lambda query: query.query)
def query_text(inline_query):
    uid = inline_query.from_user.id
    user = add_user(uid)
    text = inline_query.query
    spl = text.split(' ')
    for i in range(9):
        try:
            spl[i]
        except:
            spl.append('')
    if spl[0] == 'all':
        blocks = models.Data.filter(user=user)
        if len(blocks) == 0:
            r = types.InlineQueryResultArticle(1, "", types.InputTextMessageContent(ga('unit_n', user.lang)))
            bot.answer_inline_query(inline_query.id, [r], cache_time=1, is_personal=True)
        else:
            r = []
            i = 1
            for block in blocks:
                r.append(types.InlineQueryResultArticle(i, block.name + ' ' + ga('enc', user.lang), types.InputTextMessageContent(return_block_text_enc(block, user))))
                i+=1
            bot.answer_inline_query(inline_query.id, r, cache_time=1, is_personal=True)
    else:
        try:
            block = models.Data.get(uuid=spl[0])
            if block.user != user:
                r = types.InlineQueryResultArticle(1, ga('block_not_found', user.lang), types.InputTextMessageContent(ga('block_not_found', user.lang)))
                bot.answer_inline_query(inline_query.id, [r])
            else:
                if spl[1] != '':
                    data = get_data(block, spl[1])
                    if data[0] == '':
                        r = types.InlineQueryResultArticle(1, ga('pass_not_ex', user.lang), types.InputTextMessageContent(ga('pass_not_ex', user.lang)))
                        r1 = types.InlineQueryResultArticle(2, block.name + ' ' + ga('enc', user.lang), types.InputTextMessageContent(return_block_text_enc(block, user)))
                        bot.answer_inline_query(inline_query.id, [r, r1], is_personal=True)
                    else:
                        r = types.InlineQueryResultArticle(1, ga('block', user.lang)+f' {block.name}', types.InputTextMessageContent(return_block_text(block, data, user)))
                        bot.answer_inline_query(inline_query.id, [r], is_personal=True, cache_time=1)
                else:
                    r = types.InlineQueryResultArticle(1, ga('enter_pass', user.lang), types.InputTextMessageContent(ga('enter_pass', user.lang)))
                    r1 = types.InlineQueryResultArticle(2, block.name + ' ' + ga('enc', user.lang), types.InputTextMessageContent(return_block_text_enc(block, user)))
                    bot.answer_inline_query(inline_query.id, [r, r1], is_personal=True)
        except Exception as e:
            print(e)
            r = types.InlineQueryResultArticle(1, ga('block_not_found', user.lang), types.InputTextMessageContent(ga('block_not_found', user.lang)))
            bot.answer_inline_query(inline_query.id, [r])

@bot.callback_query_handler(func=lambda call: True)
def callback_inline(call):
    text = call.data
    uid = call.from_user.id
    user = models.User.get(user_id=uid)
    mid = call.message.message_id
    spl = text.split('_')
    id = int(call.message.json['chat']['id'])
    for i in range(9):
        try:
            spl[i]
        except:
            spl.append('')
    if spl[0] == 'delete-message':
        bot.delete_message(id, mid)
    elif spl[0] == 'delete':
        models.Data.get(uuid=spl[1]).delete_instance()
        bot.delete_message(id, mid)
    elif spl[0] == 'rename':
        bot.send_message(id, ga('enter_new_name', user.lang))
        user.action = text
        user.save()
    elif spl[0] == 'reset-pass':
        bot.send_message(id, ga('enter_old_pass', user.lang))
        user.action = text
        user.save()
    elif spl[0] == 'reset-data-login':
        bot.send_message(id, ga('enter_pass', user.lang))
        user.action = text
        user.save()
    elif spl[0] == 'reset-data-pass':
        bot.send_message(id, ga('enter_pass', user.lang))
        user.action = text
        user.save()
    elif spl[0] == 'update-block-msg':
        bot.send_message(id, ga('enter_pass', user.lang))
        user.action = text + '_' + str(mid)
        user.save()
    elif spl[0] == 'reset-data-note':
        bot.send_message(id, ga('enter_pass', user.lang))
        user.action = text
        user.save()
    elif spl[0] == 'reset-data-totp':
        bot.send_message(id, ga('enter_pass', user.lang))
        user.action = text
        user.save()
    elif spl[0] == 'lang':
        user.lang = spl[1]
        user.save()
        bot.send_message(id, ga('suc', user.lang))

@bot.message_handler(commands=['admin_recover_bd'])
def admin_recover_bd(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    if uid == int(cfg['id']):
        bot.send_document(id, open('db.db', 'rb'), caption = '#db')
    else:
        bot.send_message(id, ga('access_denied',user.lang))

@bot.message_handler(commands=['start'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    lang = m.from_user
    if lang not in langs:
        lang = 'en'
    else:
        lang = 'en'
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name, lang = lang)
    bot.send_message(id, ga('start',user.lang).format(**locals()), disable_web_page_preview=True, parse_mode='html')

@bot.message_handler(commands=['settings'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    keyboard = types.InlineKeyboardMarkup()
    for l in langs:
        button_1 = types.InlineKeyboardButton(text=l, callback_data=f'lang_{l}')
        keyboard.add(button_1)
    bot.send_message(id, 'Language/Язык\n\ntranslated by yandex', disable_web_page_preview=True, parse_mode='html', reply_markup=keyboard)

@bot.message_handler(commands=['help'])
def com(message):
    m = message
    text = m.text
    id = m.chat.id
    uid = m.from_user.id
    user = add_user(id = uid, username =  m.from_user.username, firstname =  m.from_user.first_name, lastname =  m.from_user.last_name)
    bot.send_message(id, ga('help', user.lang).format(**locals()), parse_mode='html', disable_web_page_preview=True)

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
        bot.send_message(id, ga('block_limit', user.lang))
    else:
        user.action = 'data_name'
        user.save()
        markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
        cancel = types.KeyboardButton(ga('stop',user.lang))
        markup.row(cancel)
        bot.send_message(id, ga('block_name',user.lang).format(**locals()), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)

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
        bot.send_message(id, ga('you_blocks',user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
    else:
        markup = types.ReplyKeyboardRemove()
        bot.send_message(id, ga('none_blocks',user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)

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
    if text.lower() == ga('stop', user.lang).lower().replace('\n',''):
        user.action = False
        user.tmp = False
        user.save()
        markup = types.ReplyKeyboardRemove()
        bot.send_message(id, ga('stopped', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
    elif user.action == 'data_name':
        try:
            t = True
            models.Data.get(user=user,name=text)
        except Exception as e:
            print(e)
            t = False
            if len(text) >= 50:
                bot.send_message(id, ga('long', user.lang))
            else:
                markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
                cancel = types.KeyboardButton(ga('stop', user.lang))
                no = types.KeyboardButton(ga('no', user.lang))
                markup.row(no, cancel)
                tmp = {'name': text}
                user.tmp = json.dumps(tmp)
                bot.send_message(id, ga('data_login', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
                user.action = 'data_login'
                user.save()
        if t:
            bot.send_message(id, ga('data_login_exist', user.lang), disable_web_page_preview=True, parse_mode='html')
    elif user.action == 'data_login':
        if len(text) >= 100:
            bot.send_message(id, ga('long_login', user.lang))
        else:
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            cancel = types.KeyboardButton(ga('stop', user.lang))
            markup.row(cancel)
            tmp = json.loads(user.tmp)
            if text.lower() == ga('no', user.lang).replace('\n','').lower():
                tmp['login'] = False
            else:
                tmp['login'] = text
            user.tmp = json.dumps(tmp)
            bot.send_message(id, ga('data_pass', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
            user.action = 'data_password'
            user.save()
    elif user.action == 'data_password':
        if len(text) >= 3000:
            bot.send_message(id, ga('long_text', user.lang))
        else:
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            cancel = types.KeyboardButton(ga('stop', user.lang))
            no = types.KeyboardButton(ga('no', user.lang))
            markup.row(no, cancel)
            tmp = json.loads(user.tmp)
            tmp['password'] = text
            user.tmp = json.dumps(tmp)
            bot.send_message(id, ga('data_note', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
            user.action = 'data_other'
            user.save()
    elif user.action == 'data_other':
        if len(text) >= 800:
            bot.send_message(id, ga('long_text', user.lang))
        else:
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            cancel = types.KeyboardButton(ga('stop', user.lang))
            no = types.KeyboardButton(ga('no', user.lang))
            markup.row(no, cancel)
            tmp = json.loads(user.tmp)
            if text.lower() == ga('no', user.lang).replace('\n','').lower():
                tmp['other'] = False
            else:
                tmp['other'] = text
            user.tmp = json.dumps(tmp)
            bot.send_message(id, ga('data_totp', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
            user.action = 'data_totp'
            user.save()
    elif user.action == 'data_totp':
        if len(text) >= 128:
            bot.send_message(id, ga('long_text', user.lang))
        else:
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            cancel = types.KeyboardButton(ga('stop', user.lang))
            markup.row(cancel)
            tmp = json.loads(user.tmp)
            if text.lower() == ga('no', user.lang).replace('\n','').lower():
                tmp['totp'] = False
            else:
                tmp['totp'] = text
            user.tmp = json.dumps(tmp)
            bot.send_message(id, ga('data_key', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
            user.action = 'data_key'
            user.save()
    elif user.action == 'data_key':
        tmp = json.loads(user.tmp)
        add_data(user, tmp['password'], tmp['name'], text, login=tmp['login'], other=tmp['other'], totp=tmp['totp'])
        bot.send_message(id, ga('block_created', user.lang), disable_web_page_preview=True, parse_mode='html')
        user.action = False
        user.save()
    elif user.action == 'block_see':
        try:
            models.Data.get(user=user,name=text)
            user.action = 'block_open'
            user.tmp = text
            user.save()
            markup = types.ReplyKeyboardMarkup(resize_keyboard=True)
            cancel = types.KeyboardButton(ga('stop', user.lang))
            markup.row(cancel)
            bot.send_message(id, ga('block_pass', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
        except Exception as e:
            print(e)
            bot.send_message(id, ga('block_not_found', user.lang), disable_web_page_preview=True, parse_mode='html')
    elif user.action == 'block_open':
        try:
            block = models.Data.get(user=user,name=user.tmp)
            data = get_data(block, text)
            if not data[0]:
                markup = types.ReplyKeyboardRemove()
                bot.send_message(id, ga('pass_not', user.lang).format(**globals()), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
            else:
                user.action = False
                user.save()
                bot.send_message(id, return_block_text(block, data, user), disable_web_page_preview=True, parse_mode='html', reply_markup=return_settings(block, user))
        except Exception as e:
            print(e)
            markup = types.ReplyKeyboardRemove()
            bot.send_message(id, ga('block_not_found', user.lang), disable_web_page_preview=True, parse_mode='html', reply_markup=markup)
    elif spl[0] == 'rename':
        try:
            models.Data.get(name=text)
            bot.send_message(id, ga('block_rename_ex', user.lang))
        except Exception as e:
            print(e)
            if len(text) >= 50:
                bot.send_message(id, ga('long_text', user.lang))
            else:
                user.action = False
                user.save()
                block = models.Data.get(uuid=spl[1])
                block.name = text
                block.save()
                bot.send_message(id,  ga('suc', user.lang))
    elif spl[0] == 'reset-pass':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, ga('pass_not_ex', user.lang))
        else:
            user.tmp = text
            user.action = 'reset-pass-done_'+spl[1]
            user.save()
            bot.send_message(id, ga('new_pass', user.lang))
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
        bot.send_message(id, ga('pass_ch', user.lang))
    elif spl[0] == 'reset-data-login':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, ga('pass_not_ex', user.lang))
        else:
            user.tmp = text
            user.action = 'reset-data-login-done_'+spl[1]
            user.save()
            bot.send_message(id, ga('new_data', user.lang))
    elif spl[0] == 'reset-data-login-done':
        block = models.Data.get(uuid=spl[1])
        block.login = easy_encrypt(text, user.tmp, block.salt)
        block.save()
        user.tmp = False
        user.action = False
        user.save()
        bot.send_message(id, ga('suc', user.lang))
    elif spl[0] == 'reset-data-pass':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, ga('pass_not_ex', user.lang))
        else:
            user.tmp = text
            user.action = 'reset-data-pass-done_'+spl[1]
            user.save()
            bot.send_message(id, ga('new_data', user.lang))
    elif spl[0] == 'reset-data-pass-done':
        block = models.Data.get(uuid=spl[1])
        block.data = easy_encrypt(text, user.tmp, block.salt)
        block.save()
        user.tmp = False
        user.action = False
        user.save()
        bot.send_message(id, ga('suc', user.lang))
    elif spl[0] == 'reset-data-note':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, ga('pass_not_ex', user.lang))
        else:
            user.tmp = text
            user.action = 'reset-data-note-done_'+spl[1]
            user.save()
            bot.send_message(id, ga('new_data', user.lang))
    elif spl[0] == 'reset-data-note-done':
        if len(text) >= 800:
            bot.send_message(id, ga('long_text', user.lang))
        else:
            block = models.Data.get(uuid=spl[1])
            block.other = easy_encrypt(text, user.tmp, block.salt)
            block.save()
            user.tmp = False
            user.action = False
            user.save()
            bot.send_message(id, ga('suc', user.lang))
    elif spl[0] == 'reset-data-totp':
        block = models.Data.get(uuid=spl[1])
        if get_data(block, text)[0] == '':
            bot.send_message(id, ga('pass_not_ex', user.lang))
        else:
            user.tmp = text
            user.action = 'reset-data-totp-done_'+spl[1]
            user.save()
            bot.send_message(id, ga('new_data', user.lang))
    elif spl[0] == 'reset-data-totp-done':
        if len(text) >= 128:
            bot.send_message(id, ga('long_text', user.lang))
        else:
            block = models.Data.get(uuid=spl[1])
            block.totp = easy_encrypt(text, user.tmp, block.salt)
            block.save()
            user.tmp = False
            user.action = False
            user.save()
            bot.send_message(id, ga('suc', user.lang))
    elif spl[0] == 'update-block-msg':
        block = models.Data.get(uuid=spl[1])
        data = get_data(block, text)
        if data[0] == '':
            bot.send_message(id, ga('pass_not_ex', user.lang))
        else:
            user.action = False
            user.save()
            try:
                bot.edit_message_text(chat_id=id, message_id=int(spl[2]), text = return_block_text(block, data, user), disable_web_page_preview=True, parse_mode='html', reply_markup=return_settings(block, user))
            except:
                pass

bot.polling(none_stop=True, timeout=123)
