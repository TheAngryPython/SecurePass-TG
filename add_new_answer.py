import json, requests

key = json.loads(open('cfg.txt', 'r').read())['yandex']
cfg = json.loads(open('answers.txt', 'r').read())
langs = ['en', 'it', 'fr', 'de', 'uk', 'pl']
format = 'https://translate.yandex.net/api/v1.5/tr.json/translate?key={key}&text={text}&lang={lang}&format=plain'

while 1:
    try:
        name = input('name: ')
        val = input('value: ') + '\n'
        while 1:
            inp = input()
            if inp.find('EOF') != -1:
                val += inp.replace('EOF','')
                break
            val += inp + '\n'
        cfg[name] = {}
        cfg[name]['ru'] = val
        for lang in langs:
            print(f'rquesting {lang}:')
            answer = json.loads(requests.get(format.format(lang=lang,text=val,key=key)).text)['text'][0]
            cfg[name][lang] = answer
            print(answer)
        f = open('answers.txt', 'w')
        f.write(json.dumps(cfg))
        f.close()
    except:
        print('exit')
        break
