# -*- coding: utf-8 -*-
import json, requests

key = json.loads(open('cfg.txt', 'r').read())['yandex']
cfg = json.loads(open('answers.txt', 'r').read())
langs = ['ru', 'en', 'it', 'fr', 'de', 'uk', 'pl']
format = 'https://translate.yandex.net/api/v1.5/tr.json/translate?key={key}&text={text}&lang={lang}&format=plain'
orig = input(f'orig ({langs[0]}): ') or langs[0]
while orig not in langs:
    print('orig not in langs!')
    orig = input(f'orig ({langs[0]}): ') or langs[0]

while 1:
    try:
        lst = []
        name = input('name: ')
        print('value: ', end='')
        while 1:
            inp = input()
            if inp.find('EOF') != -1:
                t=inp.replace('EOF','')
                if t:
                    lst.append(t)
                val = '\n'.join(lst)
                break
            else:
                lst.append(inp)
        cfg[name] = {}
        cfg[name][orig] = val
        for lang in langs:
            if lang == orig:
                continue
            print(f'requesting {lang}:')
            answer = json.loads(requests.get(format.format(lang=lang,text=val,key=key)).text)['text'][0]
            cfg[name][lang] = answer
            print(answer)
        f = open('answers.txt', 'w')
        f.write(json.dumps(cfg))
        f.close()
    except:
        print('exit')
        break
