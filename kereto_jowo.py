#!/usr/bin/env python3
"""

(C) Copyright 2019 aphip_uhuy

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import sys
import os
import logging
import datetime
import json
from base64 import b64decode
from base64 import b64encode
import pycurl
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

logging.basicConfig(filename='kereto_jowo-' + datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S") + '.log', level=logging.DEBUG, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')


def main():
    print('=======================================================')
    print('              Nggolek Tiket V4.0.7')
    print('')
    print('This tools used to book ticket smartly')
    print('This program is secret software: you cant redistribute it and/or modify')
    print('it under the terms of the Himacrot License as published by')
    print('the Secret Software Society, either version 3 of the License, or')
    print('any later version.')
    print('')
    print('Usage: python3 kereto_jowo.py recipe')
    print('')
    print('=======================================================')
    print('')

    args = len(sys.argv)
    if args < 2:
        print('\nUsage: python3 ' + str(sys.argv[0]) + ' recipe\n')
        sys.exit()

    filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print("File path {} does not exist. Exiting...".format(filepath))
        sys.exit()

    linedata = []
    with open(filepath) as my_file:
        linedata = my_file.readlines()

    paramcheck = json.loads(linedata[0].strip())

    numretry = str(paramcheck['numretry'])
    isusingproxy = str(paramcheck['isusingproxy'])
    issetseat = str(paramcheck['issetseat'])

    if numretry == "":
        print("Num of retry cannot be blank. Exiting...")
        sys.exit()

    if isusingproxy == "":
        print("use of proxy cannot be blank. Exiting...")
        sys.exit()

    if issetseat == "":
        print("set seat cannot be blank. Exiting...")
        sys.exit()

    if issetseat == "1":
        if linedata.count < 4:
            print("please define json seat data on recipe. Exiting...")
            sys.exit()

    if issetseat == "0":
        linedata[3] = "{}"

    check_first_new(linedata[2].strip(), linedata[1].strip(), numretry, isusingproxy)

    if (check_first_new):
        kai_booktiket(linedata[0].strip(), linedata[1].strip(), checkresult, numretry, isusingproxy, issetseat, linedata[3].strip())


class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = b'kudalumpingtelek'
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(self.cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))).decode("utf8")

    def decrypt(self, data):
        raw = b64decode(data)
        iv = b'kudalumpingtelek'
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(self.cipher.decrypt(raw), AES.block_size).decode("utf8")

    def encrypt_object(self, python_obj):
        new_obj = {}
        for key, value in python_obj.items():
            value2 = AESCipher(self.key).compute_attr_value(value, 'enc')
            new_obj[key] = value2
        return new_obj

    def decrypt_object(self, enc_python_obj):
        dec_obj = {}
        for key, value in enc_python_obj.items():
            value2 = AESCipher(self.key).compute_attr_value(value, 'dec')
            dec_obj[key] = value2
        return dec_obj

    def compute_attr_value(self, value, mode):
        if type(value) is list:
            return [self.compute_attr_value(x, mode) for x in value]
        elif type(value) is dict:
            dec_obj2 = {}
            for key, value4 in value.items():
                if mode == 'dec':
                    dec_obj2[key] = AESCipher(self.key).decrypt(value4)
                else:
                    dec_obj2[key] = AESCipher(self.key).encrypt(value4)
            return dec_obj2
        else:
            if mode == 'dec':
                value3 = AESCipher(self.key).decrypt(value)
            else:
                value3 = AESCipher(self.key).encrypt(value)
            return value3


def check_first_new(checkdata, bookingdata, numretry, usingproxy):
    successCheck = False
    usingproxy = bool(int(usingproxy) > 0)
    retrylogin = 0
    maxretrylogin = int(numretry)
    resCheck = ""
    pwd = b'telo_pendem_tele'

    while retrylogin < maxretrylogin and not successCheck:
        try:
            reqcheck = json.loads(checkdata)
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Trying search seat : ' + str(retrylogin))
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> search seat to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data search seat to kai :')

            target = 'https://midsvc-rts40.kai.id/rtsngmid/mobile/getschedulecity2city'
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Accept': 'application/json, text/plain, */*',
                'Host': 'midsvc-rts40.kai.id',
                'source': 'mobile',
                'User-Agent': 'KAI/2.6.0'}

            bookdataEncrypt = '{"staorigincode":"' + AESCipher(pwd).encrypt(reqcheck['org']) + '","stadestinationcode":null,"departuredate":"' + AESCipher(pwd).encrypt(reqcheck['date']) + '","passenger":"' + AESCipher(pwd).encrypt(reqcheck['adult']) + '","infant":"' + AESCipher(pwd).encrypt(reqcheck['child']) + '","seatclass":"' + AESCipher(pwd).encrypt(reqcheck['seatclass']) + '","roundTripIntercity":"0eM4cVgalmQlxb9shTnWjw==","returndate":"' + AESCipher(pwd).encrypt(reqcheck['date_return']) + '","orgname":"' + AESCipher(pwd).encrypt(reqcheck['orgname']) + '","destname":"' + AESCipher(pwd).encrypt(reqcheck['destname']) + '","searchLocal":"0eM4cVgalmQlxb9shTnWjw==","paramorigin":"' + AESCipher(pwd).encrypt(reqcheck['org']) + '","paramdestination":"' + AESCipher(pwd).encrypt(reqcheck['destname']) + '","tripdate":"' + AESCipher(pwd).encrypt(reqcheck['date']) + '"}'
            logging.info('log search data : ' + bookdataEncrypt)
            r = requests.post(target, data=bookdataEncrypt, headers=headers, timeout=10)

            if r.status_code != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(r.text)
                logging.warning('error search seat res : rc-> ' + str(r.status_code) + ' err-> ' + r.text)
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check res : ' + str(r.status_code))
            resCheck = json.loads(r.text)
            logging.info('check set res : ' + str(resCheck['code']))

            if resCheck['code'] == '00':
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check availability seat')
                if(len(resCheck['payload']) > 0):
                    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check ' + str(len(resCheck['payload'])) + ' train')
                    for i in resCheck['payload']:
                        if i['noka'] == reqcheck['train_no']:
                            if i['subclass'] == reqcheck['subclass']:
                                if i['availability'] >= int(reqcheck['adult']):
                                    print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' hooray seat found process -> check kursi : ' + str(i['availability']))
                                    global checkresult
                                    checkresult = i
                                    return successCheck
                                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' opps seat full process -> check kursi : ' + str(i['availability']))
                                raise Exception
                            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' opps no train class found')
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' opps no seat found')
                raise Exception
            else:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> check res code : ' + str(resCheck['code']) + ' - ' + str(resCheck['message']))
                raise Exception
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrylogin += 1
            if retrylogin >= maxretrylogin:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return successCheck


def retry_login_new(logindata, numretry, usingproxy):
    successlogin = False
    usingproxy = bool(int(usingproxy) > 0)
    retrylogin = 0
    maxretrylogin = int(numretry)
    reslogin = ""

    while retrylogin < maxretrylogin and not successlogin:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Retrying login no : ' + str(retrylogin))
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> login to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data login to kai :')
            # print(logindata)
            # print('#########################################')
            target = 'https://midsvc-rts40.kai.id/rtsngmid/cred/signin'
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Accept': 'application/json, text/plain, */*',
                'Host': 'midsvc-rts40.kai.id',
                'source': 'mobile',
                'User-Agent': 'KAI/2.6.0'}

            if(usingproxy):
                proxies = {'https': 'http://localhost:3128'}

            r = requests.post(target, data=logindata, headers=headers, timeout=10)

            if r.status_code != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(r.text)
                logging.warning('error login res : ' + r.text)
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> login res : ' + str(r.text))
            reslogin = json.loads(r.text)
            logging.info('login res : ' + str(reslogin))            
            successlogin = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrylogin += 1
            if retrylogin >= maxretrylogin:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return reslogin


def booking_class_new(loginres, logindata, bookingdata, checkdata, numretry, usingproxy):
    successbook = False
    usingproxy = bool(int(usingproxy) > 0)
    retrybook = 0
    maxretrybook = int(numretry)
    resbooking = ""
    pwd = b'telo_pendem_tele'

    while retrybook < maxretrybook and not successbook:
        try:
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Retrying no : ' + str(retrybook))
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data booking to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data booking to kai ...')
            tokenhead = loginres['payload']
            reqbook = json.loads(bookingdata)
            checkdataraw = checkdata
            # prepare data booking
            passengerdataencrypt = ""
            
            for i in reqbook['passenger']:
                i['idnum'] = AESCipher(pwd).encrypt(i['idnum'])
                i['name'] = AESCipher(pwd).encrypt(i['name'])
                i['psgtype'] = AESCipher(pwd).encrypt(i['psgtype'])
                passengerdataencrypt = i

            bookdataraw = ('{"propscheduleid":"' + AESCipher(pwd).encrypt(checkdataraw["propscheduleid"]) + '",'
                           '"tripid":"' + AESCipher(pwd).encrypt(checkdataraw['tripid']) + '",'
                           '"orgid":"' + AESCipher(pwd).encrypt(str(checkdataraw['orgid'])) + '",'
                           '"desid":"' + AESCipher(pwd).encrypt(str(checkdataraw['desid'])) + '",'
                           '"orgcode":"' + AESCipher(pwd).encrypt(checkdataraw['orgcode'] )+ '",'
                           '"destcode":"' + AESCipher(pwd).encrypt(checkdataraw['destcode']) + '",'
                           '"tripdate":"' + AESCipher(pwd).encrypt(checkdataraw['tripdate']) + '",'
                           '"departdate":"' + AESCipher(pwd).encrypt(checkdataraw['tripdate']) + '",'
                           '"noka":"' + AESCipher(pwd).encrypt(checkdataraw['noka']) + '",'
                           '"extrafee":"rjs6uhCMGfOFx7+/9bzOFw==",'
                           '"wagonclasscode":"' + AESCipher(pwd).encrypt(checkdataraw['wagonclasscode']) + '",'
                           '"wagonclassid":"' + AESCipher(pwd).encrypt(str(checkdataraw['wagonclassid'])) + '",'
                           '"customername":"' + AESCipher(pwd).encrypt(reqbook['name']) + '",'
                           '"phone":"' + AESCipher(pwd).encrypt(reqbook['phone']) + '",'
                           '"email":"' + AESCipher(pwd).encrypt(reqbook['email']) + '",'
                           '"subclass":"' + AESCipher(pwd).encrypt(checkdataraw['subclass']) + '",'
                           '"totpsgadult":"' + AESCipher(pwd).encrypt(reqbook['num_pax_adult']) + '",'
                           '"totpsgchild":"rjs6uhCMGfOFx7+/9bzOFw==",'
                           '"totpsginfant":"' + AESCipher(pwd).encrypt(reqbook['num_pax_infant']) + '",'
                           '"paxes":['+ json.dumps(passengerdataencrypt) +']'
                           '}')

            logging.info('check bookdataraw : ' + bookdataraw)

            target = 'https://midsvc-rts40.kai.id/rtsngmid/mobile/booking'
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Accept': 'application/json, text/plain, */*',
                'authorization': 'Bearer ' + tokenhead + '',
                'Host': 'midsvc-rts40.kai.id',
                'Accept-Encoding': 'gzip, deflate',
                'source': 'mobile',
                'User-Agent': 'okhttp/3.12.1'}

            if(usingproxy):
                proxies = {'https': 'http://localhost:3128'}

            r = requests.post(target, data=bookdataraw, headers=headers, timeout=10)

            if r.status_code != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(r.text)
                logging.warning('error booking res : ' + r.text)
                if r.text == '{"error":"token_invalid"}' or (r.text == '{"error":"token_expired"}'):
                    loginres = retry_login_new(logindata, numretry, usingproxy)
                raise Exception

            resbooking = json.loads(r.text)
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> booking res : ' + resbooking['code'] + '-' + resbooking['message'])
            logging.info('booking res : ' + str(resbooking))            
            successbook = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrybook += 1
            if retrybook >= maxretrybook:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return resbooking


def payment1_class(loginres, logindata, unitcodepay, paycode, netamount, numretry, usingproxy):
    successpay = False
    usingproxy = bool(int(usingproxy) > 0)
    retrypay = 0
    maxretrypay = int(numretry)
    respay = ""
    pwd = b'telo_pendem_tele'

    while retrypay < maxretrypay and not successpay:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data booking phase 2 to kai :')

            datapayment = 'paycode=' + paycode + ',paytypecode=ATM,channelcodepay=MAPP,netamount=' + str(netamount) + ',tickettype=R,shiftid=15138,unitcodepay=' + unitcodepay + ',paysource=RTSNG'
            datapaymentencrypt = AESCipher(pwd).encrypt(datapayment)
            datasend = '{"data":["' + datapaymentencrypt + '"]}'
            tokenhead = loginres['payload']
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data booking phase 2 to kai ...')

            print('booking code : ' + unitcodepay)
            print('order code : ' + paycode)
            print('net ammount : ' + str(netamount))

            target = 'https://midsvc-rts40.kai.id/rtsngmid/py_service/mobile/checkout'
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Accept': 'application/json, text/plain, */*',
                'authorization': 'Bearer ' + tokenhead + '',
                'Host': 'midsvc-rts40.kai.id',
                'Accept-Encoding': 'gzip, deflate',
                'source': 'mobile',
                'User-Agent': 'okhttp/3.12.1'}

            if(usingproxy):
                proxies = {'https': 'http://localhost:3128'}

            logging.info('check paymentdata : ' + datasend)
            r = requests.post(target, data=datasend, headers=headers, timeout=10)

            if r.status_code != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(r.text)
                logging.warning('error pay res : ' + r.text)
                if r.text == '{"error":"token_invalid"}' or (r.text == '{"error":"token_expired"}'):
                    loginres = retry_login_new(logindata, numretry, usingproxy)
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> booking phase 2 res : ' + r.text)
            respay = json.loads(r.text)
            logging.info('pay res : ' + str(respay))            
            successpay = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retrypay += 1
            if retrypay >= maxretrypay:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return respay


def flag_class(loginres, logindata, commonPaycode, numretry, usingproxy):
    successflag = False
    usingproxy = bool(int(usingproxy) > 0)
    retryflag = 0
    maxretryflag = int(numretry)
    resflag = ""

    while retryflag < maxretryflag and not successflag:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data booking flag to kai :')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data booking flag to kai ...')

            print('commonPaye code : ' + commonPaycode)

            tokenhead = loginres['payload']

            target = 'https://midsvc-rts40.kai.id/rtsngmid/mobile/info/updatepaytype/' + commonPaycode + '/227'
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Accept': 'application/json, text/plain, */*',
                'authorization': 'Bearer ' + tokenhead + '',
                'Host': 'midsvc-rts40.kai.id',
                'Accept-Encoding': 'gzip, deflate',
                'source': 'mobile',
                'User-Agent': 'okhttp/3.12.1'}

            if(usingproxy):
                proxies = {'https': 'http://localhost:3128'}

            r = requests.get(target, headers=headers, timeout=10)

            if r.status_code != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(r.text)
                logging.warning('error flag res : ' + r.text)
                if r.text == '{"error":"token_invalid"}' or (r.text == '{"error":"token_expired"}'):
                    loginres = retry_login_new(logindata, numretry, usingproxy)
                raise Exception

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> booking flag res : ' + r.text)
            resflag = r.text
            logging.info('flag res : ' + r.text)
            successflag = True

            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retryflag += 1
            if retryflag >= maxretryflag:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                sys.exit()

    return resflag


def seat_class(loginres, logindata, bookcode, numcode, numretry, usingproxy, seatdata):
    successseat = False
    usingproxy = bool(int(usingproxy) > 0)
    retryseat = 0
    maxretryseat = 1
    resseat = ""

    while retryseat < maxretryseat and not successseat:
        try:
            print('#########################################')
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> sending raw data set seat to kai :')

            print(seatdata)
            dataseatjson = '{"book_code": "' + bookcode + '", "passenger":[' + seatdata + ']}'
            dataseat = str(dataseatjson)
            tokenhead = loginres['payload']
            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> try sending raw data set seat to kai ...')

            print('data seat : ' + dataseat)

            buf6 = cStringIO.StringIO()
            e6 = pycurl.Curl()
            e6.setopt(
                e6.URL, 'https://kaiaccess11.kai.id/api/v12/manual_seat')
            e6.setopt(e6.HTTPHEADER, [
                'Content-Type: 	application/json;charset=utf-8', 'accept: application/json, text/plain, */*',
                'authorization: Bearer ' + tokenhead + '',
                'source: mobile', 'User-Agent: okhttp/3.4.1'])
            e6.setopt(e6.POST, 1)
            e6.setopt(
                e6.POSTFIELDS, dataseat)
            e6.setopt(e6.WRITEFUNCTION, buf6.write)
            e6.setopt(e6.VERBOSE, False)
            e6.setopt(e6.SSL_VERIFYPEER, 0)
            e6.setopt(e6.SSL_VERIFYHOST, 0)

            if(usingproxy):
                e6.setopt(e6.PROXY, 'proxy3.bri.co.id')
                e6.setopt(e6.PROXYPORT, 1707)
                e6.setopt(e6.PROXYTYPE, e6.PROXYTYPE_HTTP)

            e6.perform()

            ''' if e3.getinfo(e3.HTTP_CODE) != 200:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> opps found error :')
                print(buf3.getvalue())
                logging.info('error pay res : ' + str(buf3.getvalue()))
                if str(buf3.getvalue()) == '{"error":"token_invalid"}' or (str(buf3.getvalue()) == '{"error":"token_expired"}'):
                    loginres = retry_login(logindata, numretry, usingproxy)
                raise Exception '''

            print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' process -> set seat res : ' + buf6.getvalue())
            resseat = json.loads(buf6.getvalue())
            logging.info('pay res : ' + str(resseat))
            buf6.close()
            successseat = True
            print('#########################################')
            print('')

        except Exception as err:
            print(err)
            # time.sleep(20)
            retryseat += 1
            if retryseat >= maxretryseat:
                print(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' Too many error attempts .. Quiting .. ')
                # sys.exit()

    return resseat


def kai_booktiket(logindata, bookingdata, checkdata, numretry, usingproxy, setseat, seatdata):
    success = False
    usingproxy = bool(int(usingproxy) > 0)
    retry = 0
    maxretry = int(numretry)

    while retry < maxretry and not success:
        try:
            reslogin = retry_login_new(logindata, numretry, usingproxy)

            if reslogin['code'] == "00":
                resbooking = booking_class_new(reslogin, logindata, bookingdata, checkdata, numretry, usingproxy)

                if resbooking['code'] == "00":
                    unitcodepay = resbooking['payload']['unitcode']
                    paycode = resbooking['payload']['paycode']
                    netamount = resbooking['payload']['netamount']
                    if setseat == "1":
                        resseat = seat_class(reslogin, logindata, unitcodepay, paycode, numretry, usingproxy, seatdata)

                    respayment = payment1_class(reslogin, logindata, unitcodepay, paycode, netamount, numretry, usingproxy)

                    if respayment['code'] == "00":
                        commonPaycode = respayment['payload']['commonPaycode']
                        resflag = flag_class(reslogin, logindata, commonPaycode, numretry, usingproxy)

                        print(resflag)
                        success = True

        except Exception as er:
            print(er)
            # logging.error('Exception : ' + er)
            # time.sleep(20)
            # continue

        retry += 1
        print('=======================================================')


if __name__ == '__main__':
    checkresult = ''
    main()
