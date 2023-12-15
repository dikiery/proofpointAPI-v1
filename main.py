import inspect
import json
import os.path
import websocket
import time

import config
from log_proccessing import *


ws = None
wsapp = None
#run debug log
#websocket.enableTrace(True)

#ws = websocket.WebSocket()

script_path=os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
log_path=script_path+"\logs"

def create_log_file(log_file_name):
    if not os.path.isfile(log_path + "\\"+ log_file_name):
        lg =open(log_path + "\\"+ log_file_name,"x")
        lg = open(log_path + "\\"+ log_file_name, "w")
    else:
        lg = open(log_path + "\\"+ log_file_name, "a")

    return lg


def on_message(wsapp, message):
    if 'sinceTime' in http_url:
        strmessage = str(message)
    else :
        strmessage = str(message, 'UTF-8')

    #Processign the raw log
    #
    #
    try :

        jsonmessage=json.loads(strmessage)
        write_system_log('Receive Log from GUID :'+str(jsonmessage["guid"]))
    except Exception as ex:
        write_system_log(ex)

    get_local_log(jsonmessage)

    # try:
    #     log_message_score_overall = str(jsonmessage["filter"]["modules"]["spam"]["scores"]["overall"])
    # except:
    #     log_message_score_overall = ''
    #     pass
    # print('=============Raw Message==================')
    # write the raw log into file log_sample.log
    # lg = create_log_file("threat_log.log")
    #log_message_date = str(jsonmessage["ts"])
    #log_message_guid = str(jsonmessage["guid"])
    #print('========JSON Filter===== ' + log_message_date + ' ==================')
    #if (log_message_score_overall != '0' and log_message_score_overall != '' ):
    #print("Trher :"+log_message_score_overall)
    #print(strmessage, file=lg)




    

n=0
#Get Config

try :
    config.get_config()
except:
    write_system_log("Failed to load the configuration")

http_url=config.config_url
http_headers={"Authorization":"Bearer "+config.config_http_header_auth}







#while(True):
 #   print("test"+str(n))

#ws=websocket()
# while(True):
#     time.sleep(1)
i = 0
while i < 3:
    i += 1
    try:
        ws = websocket.create_connection(http_url, header=http_headers)
    except Exception as ext:
        write_system_log('Failed Create Connection to Server')
        write_system_log(ext)
        write_system_log('Reconnect to websocket ...')
        time.sleep(2)
        continue



#SystemExit

# validate if connection secussfully connected
#
i = 0
while i < 3:
    i += 1
    if ws is not None:
        write_system_log('Successfull Connect to '+ http_url)
        #
        # Build the stream connection
        #
        try:
            wsapp = websocket.WebSocketApp(http_url, header=http_headers, on_message=on_message)
        except Exception as ex:
            write_system_log(ex)
            continue

        if wsapp is not None:
            write_system_log('Start to listen the socket ...')
            try:
                wsapp.run_forever()
            except Exception as ex:
                write_system_log(ex)
                continue


#print(ws.getheaders())
#print(ws.getsubprotocol())
#print(ws2.status)
#wsapp = websocket.WebSocketApp(http_url, header=http_headers, on_message=on_message)
#websocket.WebSocket.status()






