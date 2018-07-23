from iota import Iota


import socket
import json
import sys

def prepareJSONstring(message_type, data=None, signature=None, verification=None):
    """
    Prepares the JSON message format to be sent to the Seller
    :param message_type: HELLO/ORDER/DATA_ACK/PAYMENT_ACK/EXIT
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

#IOTA setup
client = 'http://node02.iotatoken.nl:14265' #Look on www.iotatoken.nl for downtime announcements and real time info
seed = ''
#initialize IOTA API
api = Iota(client, seed)
wallet = api.get_new_addresses(count=1)
wallet = str(wallet['addresses'][0].address)


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = 6113
ip = 'localhost'
s.connect((ip,port))

s.send(prepareJSONstring('HELLO')) #send HELLO message to broker


message_json = json.loads(s.recv(2048)) #receive MENU
print json.dumps(message_json, sort_keys=True, indent=4, separators=(',',':')) #pretty print received MENU message

data = message_json['data']
data_json = json.loads(data)

broker_payment_address = data_json['payment-address']
broker_public_key = data_json['broker-public-key']

menu_json = data_json['menu']
#menu_json = json.loads(menu)

#prompt client for service level selection
serviceSelected = False
while not serviceSelected:
	service = raw_input('Input requested service level (level0,level1,level2 etc.):')
	if(service == 'level0'):
		print "level0 is free"
		continue
	confirm = raw_input('The price is ' + menu_json[str(service)] + ' . Is this OK? (y/n):')
	if(confirm == 'y'):
		serviceSelected = True


#send payment transaction to broker_payment_address (IOTA)

#send ORDER message to broker/controller 
with open('order.json') as orderFile:
	orderData = orderFile.read()
	orderData = json.loads(orderData)

order = prepareJSONstring("ORDER",json.dumps(orderData),"test-signature","test-txid")
s.send(order)
print order

