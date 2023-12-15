import inspect
import os.path
import re
import configparser
import datetime
#
#
# url=
# header_authorization=
# mail_log_file_path=
global script_path
script_path=os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))


# Configuration Path Information
#

config_path=script_path+"\config"
config_path_file=config_path+"\config.ini"

#
# Default Param
#

config_url=''
config_http_header_auth=''
config_event_log_path=''
config_event_log_name=''
config_system_log_path=''
config_system_log_name=''



def validation():
    if not os.path.isfile(config_path_file):
       print("Config file config.ini was not found, Please  "+config_path)
    else:
        read_config_files = open(config_path_file, 'r')
        for cfg in read_config_files:
            result=re.search(r'[\w\-\.]+@([\w-]+)((\.[\w-]+)+|(\.)?)', cfg)

#            if result.group() == '':

    return True

def get_config():

    load_config_file()
    return


def load_config_file():
    if validation():
        cnf=configparser.ConfigParser()
        cnf.read(config_path_file)

        #Get the URL Infomation from config file
        #
        global config_url
        config_url=cnf.get('AUTH','URL')

        if 'https:' in config_url:
            #print("yes")
            config_url=config_url.replace('https','wss')
        else:
            if 'http:' in config_url:
                config_url = config_url.replace('http:', 'ws:')

        #Get the HTTP Header Informasion Infomation from config file
        #
        global config_http_header_auth
        config_http_header_auth = cnf.get('AUTH', 'HTTP_HEADER_AUTHORIZATION')


        # Get the Event Log Path Infomation from config file
        #
        global config_event_log_path
        config_event_log_path = cnf.get('AUTH', 'EVENT_LOG_PATH')

        global config_system_log_path
        config_system_log_path = script_path+"\\logs"

        #Get Date Format
        #
        dt = datetime.datetime
        str_dt=dt.now().strftime('%Y%m%d')

        #Set event log name with Date Format
        #
        global config_event_log_name
        config_event_log_name = str_dt+'_event_message.log'

        global config_system_log_name
        config_system_log_name = str_dt + '_collector.log'
    return


#get_config()
#print(config_url+"| header : auth"+config_http_header_auth)
#print(config_event_log_path)
#print(config_system_log_path)


#dt = datetime.datetime
#str_dt=dt.now().strftime('%Y-%m-%d:%H%M')
#print(str_dt)