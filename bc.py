#!/usr/bin/python3

import hashlib
import os
import random
import binascii
import ecdsa
import base58
import datetime
import webbrowser
import PySimpleGUI as sg
from json import (load as jsonload, dump as jsondump)
from os import path
import json
import hmac
import base64

start_time = datetime.datetime.now()

def bip(num):
    with open('BIP0039.txt', 'r') as f:
        words = f.read().split()
        for word in words:
            sent = [random.choice(words)
                for word in range(int(num))]
            return ' '.join(sent)

def passw(filename):
    try:
        with open(filename, 'r') as f:
            words = f.read().split()
            for word in words:
                sent = [random.choice(words)
                        for word in range(int(1))]
                return ''.join(sent)
    except FileNotFoundError:
        pass
    except TypeError:
        pass


def hmac512(mnemonic, passphrase):
        hmac512 = hashlib.pbkdf2_hmac('sha512', mnemonic.encode(), ("mnemonic"+passphrase).encode(), 2048)
        return binascii.hexlify(hmac512)

def master(hmacsha512):
    first = hmacsha512[:64].decode()
    second = hmacsha512[64:].decode()
    return first


def pubkey(masterkey):
    privatekey = binascii.unhexlify(masterkey)
    s = ecdsa.SigningKey.from_string(privatekey, curve = ecdsa.SECP256k1)
    return '04' + binascii.hexlify(s.verifying_key.to_string()).decode('utf-8')

def addr(public_key):
    output = []; alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    var.update(hashlib.sha256(binascii.unhexlify(public_key.encode())).digest())
    var = '00' + var.hexdigest() + hashlib.sha256(hashlib.sha256(binascii.unhexlify(('00' + var.hexdigest()).encode())).digest()).hexdigest()[0:8]
    count = [char != '0' for char in var].index(True) // 2
    n = int(var, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def wif(masterkey):
    var80 = "80"+masterkey
    var = hashlib.sha256(binascii.unhexlify(hashlib.sha256(binascii.unhexlify(var80)).hexdigest())).hexdigest()
    return str(base58.b58encode(binascii.unhexlify(str(var80) + str(var[0:8]))), 'utf-8')

def database(address):
    with open("data-base", "r") as m:
        add = m.read().split()
        for ad in add:
            continue
        if address in add:
            data = open("Win.txt","a")
            data.write("Bingo " + str(sect)+"\n" +str(address)+"\n"+str(WIF)+"\n"+"\n")
            data.close()
            return 'Bingo'
        else:
            i = 'No luck'
            return i


SETTINGS_FILE = path.join(path.dirname(__file__), r'settings_file.cfg')
DEFAULT_SETTINGS = {'theme': sg.theme()}
SETTINGS_KEYS_TO_ELEMENT_KEYS = {'theme': '-THEME-'}

def load_settings(settings_file, default_settings):
    try:
        with open(settings_file, 'r') as f:
            settings = jsonload(f)
    except Exception as e:
        sg.popup_quick_message(f'exception {e}', 'No settings file found... will create one for you', keep_on_top=True, background_color='red', text_color='white')
        settings = default_settings
        save_settings(settings_file, settings, None)
    return settings


def save_settings(settings_file, settings, values):
    if values:      
        for key in SETTINGS_KEYS_TO_ELEMENT_KEYS:  
            try:
                settings[key] = values[SETTINGS_KEYS_TO_ELEMENT_KEYS[key]]
            except Exception as e:
                print(f'Problem updating settings from window values. Key = {key}')

    with open(settings_file, 'w') as f:
        jsondump(settings, f)

    sg.popup('Settings saved')

def create_settings_window(settings):
    sg.theme(settings['theme'])

    def TextLabel(text): return sg.Text(text+':', justification='r', size=(15,1))

    layout = [  [sg.Text('Settings', font='Any 15')],
                [TextLabel('Theme'),sg.Combo(sg.theme_list(), size=(20, 20), key='-THEME-')],
                [sg.Button('Save'), sg.Button('Exit')]  ]

    window = sg.Window('Settings', layout, keep_on_top=True, finalize=True)

    for key in SETTINGS_KEYS_TO_ELEMENT_KEYS:
        try:
            window[SETTINGS_KEYS_TO_ELEMENT_KEYS[key]].update(value=settings[key])
        except Exception as e:
            print(f'Problem updating PySimpleGUI window from settings. Key = {key}')

    return window


def create_main_window(settings):
    sg.theme(settings['theme'])

    menu_def = [['&Menu', ['&Settings', 'E&xit']]]

    layout = [[sg.Menu(menu_def)],
              [sg.Text('Number of mnemonic words', size=(30,1), font=('Comic sans ms', 10)),
               sg.Spin(values=('3', '6', '9', '12', '15', '18', '21', '24'),size=(3,1), key='num'), sg.Text('', size=(17,1)),
               sg.Button('', key='paypal', size=(12,1), font=('Helvetica', 9), button_color=(sg.theme_background_color(), sg.theme_background_color()),
                         image_filename='paypal.png', image_size=(80, 50), image_subsample=2, border_width=0),
               sg.Button('', key='bitcoin', size=(12,1), font=('Helvetica', 9), button_color=(sg.theme_background_color(), sg.theme_background_color()),
                         image_filename='bitcoin.png', image_size=(80, 60), image_subsample=2, border_width=0)],
              [sg.Text('This program has been running for... ', size=(30,1), font=('Comic sans ms', 10)),
               sg.Text('', size=(30,1), font=('Comic sans ms', 10), key='_DATE_')],
              [sg.Text('')],
              [sg.Output(size=(87, 20), font=('Comic sans ms', 8), key='out')],
              [sg.Text('Select passwords file', size=(10,1), font=('Comic sans ms', 10)),sg.In(size=(67, 1),key='-in-'), sg.FileBrowse()],
              [sg.Button('Start/Stop',  font=('Comic sans ms', 10))]]

    return sg.Window('Bitcoin wallet cracker',
                     layout=layout,
                     default_element_size=(9,1))



def main():
    window, settings = None, load_settings(SETTINGS_FILE, DEFAULT_SETTINGS )
    generator = False
    while True:
        if window is None:
            window = create_main_window(settings)
        event, values = window.Read(timeout=10)
        window.Element('_DATE_').Update(str(datetime.datetime.now()-start_time))
        if event in (None, 'Exit'):
            break
        elif event == 'Start/Stop':
            generator = not generator
        if generator:
            filename = values['-in-'].rstrip()
            num = values['num']
            mnemonic = bip(num)
            passphrase = passw(filename)
            hmacsha512 = hmac512(mnemonic, passphrase)
            masterkey = master(hmacsha512)
            public_key = pubkey(masterkey)
            address = addr(public_key)
            WIF = wif(masterkey)
            data_base = database(address)
            print('mnemonic and passphrase:   '+str(mnemonic)+ ' ' +str(passphrase)+'\n'+
                  'private key:                           '+str(masterkey)+'\n'+
                  'address:                                 '+str(address)+'\n'+
                  'wif:                                        '+str(WIF)+"\n"+
                  'address with balance:           '+str(data_base)+'\n\n')
            
        elif event == 'Settings':
            event, values = create_settings_window(settings).read(close=True)
            if event == 'Save':
                window.close()
                window = None
                save_settings(SETTINGS_FILE, settings, values)


        elif event == 'paypal':
            webbrowser.open_new_tab("https://www.paypal.com/donate/?cmd=_s-xclick&hosted_button_id=PFB6A6HLAQHC2&source=url")
        
        elif event == 'bitcoin':
            webbrowser.open_new_tab("https://commerce.coinbase.com/checkout/149a6235-ec7e-4d3b-a1ae-b08c4f08b4f6")

    
    window.Close()
    
main()

