# Copyright (c) 2018, Autonomous Networks Research Group. All rights reserved.
#     Contributors: David Chen, Zhiyue Zhang, Rahul Radhakrishnan
#     Read license file in main directory for more details  

import iota

import Crypto.Hash.MD5 as MD5
import Crypto.PublicKey.RSA as RSA

import socket
import json
import sys

#IOTA setup
client = 'http://node02.iotatoken.nl:14265' #Look on www.iotatoken.nl for downtime announcements and real time info
seed = ''
#initialize IOTA API
api = iota.Iota(client, seed)
wallet = api.get_new_addresses(count=1)
wallet = str(wallet['addresses'][0].address)

#generate signature key
signature_key = RSA.generate(2048, e=65537)

#tcp connection to controller 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 6113
ip = 'localhost'
s.connect((ip,port))

def signData(plaintext,key):
    """
    Signs the Data
    :param plaintext: String to be signed
    :return: signature<Tuple>
    """
    hash = MD5.new(plaintext).digest()
    signature = key.sign(hash, '')
    return signature



def prepareJSONstring(message_type, data=None, signature=None, verification=None):
    """
    Prepares the JSON message format to be sent to the Seller
    :param message_type: HELLO/PREORDER/ORDER/DATA_ACK/PAYMENT_ACK/EXIT
    :param data: Corresponding data
    :param signature: Signed Data
    :param verification: Address or the transaction ID in Tangle/Blockchain
    :return: JSON dictionary
    """

    json_data = {}

    json_data['message_type'] = message_type

    if data:
        json_data['data'] = data
    else:
        json_data['data'] = ""
    if signature:
        json_data['signature'] = signature
    else:
        json_data['signature'] = ""
    if verification:
        json_data['verification'] = verification
    else:
        json_data['verification'] = ""

    return json.dumps(json_data)


def sendTransaction(transaction,api):
    try:
        bundle = api.send_transfer(depth=2, transfers=[transaction])
        url = "https://thetangle.org/bundle/" + str(bundle["bundle"].hash)
        print url
        #.info(url)
        return str(api.find_transactions([bundle["bundle"].hash])['hashes'][0])
    except iota.adapter.BadApiResponse as error:
        #logger.error(error)
        return False


def prepareTransaction(api, address, message=None, value=0):
    """
    Prepares the transaction to be made through the distributed ledger
    :param message: Message for the payment
    :param value: Amount of cryptocurrencies to be sent
    :return: Transaction ID/ Address/ Transaction hash
    """
    if message:
        message = iota.TryteString.from_string(message)
    tag = iota.Tag(b"SDPPBUYER")

    transaction = iota.ProposedTransaction(
        address=address,
        value=value,
        message=message,
        tag=tag
    )

    return sendTransaction(transaction,api)


s.send(prepareJSONstring('HELLO')) #send HELLO message to broker


message_json = json.loads(s.recv(2048)) #receive MENU
print json.dumps(message_json, sort_keys=True, indent=4, separators=(',',':')) #pretty print received MENU message

data = message_json['data']
data_json = json.loads(data)

broker_payment_address = iota.Address(str(data_json['payment-address']))
broker_public_key = RSA.importKey(data_json['broker-public-key'])

menu_json = data_json['menu']
#menu_json = json.loads(menu)

#prompt client for service level selection
serviceSelected = False
while not serviceSelected:
	service = raw_input('Input requested service level (level0,level1,level2 etc.):')
	if(service == 'level0'):
		print "level0 is free"
		continue
	confirm = raw_input('The price is ' + menu_json[str(service)] + ' per second . Is this OK? (y/n):')
	if(confirm == 'y'):
		serviceSelected = True

#prompt client for ip pair
ip1 = raw_input('Enter IP1:')
ip2 = raw_input('Enter IP2:')

#prompt client for time 
time = raw_input('Enter time (s):')

#send PREORDER message to broker/controller
checkData = {}
checkData['ip1']=ip1
checkData['ip2']=ip2
checkData['level']=service
preorder = prepareJSONstring(message_type="PREORDER",data=json.dumps(checkData))
s.send(preorder)
print preorder

#get reply from broker/controller of PREORDER check



#send records transaction to broker_payment_address (IOTA)
message = service + ' ' + ip1 + ' ' + ip2 + ' ' + time + 's'
message_signature = signData(message,signature_key)
tx_id = prepareTransaction(api,broker_payment_address,str(message))

print "records tx_id: " + tx_id

#send payment
#price = menu_json[service]

#setting price to 0 for testing. otherwise would need to send money to wallet
price = 0

tx_id = prepareTransaction(api=api,address=broker_payment_address,value=int(price))
print "payment tx_id: " + str(tx_id)


#send ORDER message to broker/controller 
with open('order.json') as orderFile:
	orderData = orderFile.read()
	orderData = json.loads(orderData)

orderData['level'] = service
orderData['ip1'] = ip1
orderData['ip2'] = ip2 
orderData['time'] = time

order = prepareJSONstring(message_type="ORDER",data=json.dumps(orderData),verification=tx_id)
s.send(order)
print order

