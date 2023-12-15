import datetime
import re
import os
import config


def get_hash_object(log_message_url_msg):
    list_object = []
    sandboxstatsus=''
    detectedExt=''
    labeledName = ''
    md5 = ''

    for msg in log_message_url_msg:
        try:
            sandboxstatsus=msg["sandboxStatus"]
        except:
            sandboxstatsus=''

        if sandboxstatsus != '':
            detectedExt = msg["detectedExt"]
            if detectedExt != ('HTML','TXT'):
                labeledName = msg["labeledName"]
                md5 = msg["md5"]


    list_object.append(sandboxstatsus)
    list_object.append(detectedExt)
    list_object.append(labeledName)
    list_object.append(md5)
    #print(str(list_object))


    return list_object

def get_url(log_message_url_msg):
    i_msg = 0

    str_url = ''
    for msg in log_message_url_msg:
        log_message_urls = msg.get("urls")
        # log_message_urls
        i_url = 0

        # log_message_urls = log_message_url_msg.get("urls")
        for url in log_message_urls:
            str_url = url["url"]

            # try:
            #     isRewritten = url["isRewritten"]
            # except:
            #     isRewritten = url["isRewritten"]
            #     pass
            # print(str(isRewritten))
            src=str(url["src"])
            if 'http' in url["url"] and 'urldefense' in src:
                str_url = url["url"]

            else:
                if 'http' in url["url"]:
                    str_url = url["url"]
            # print("msgpart = "+str(i_msg)+" url = " + str(i_url) + " > " + str_url)
            i_url += 1

        i_msg += 1
        #print(str_url)
        break
    return str_url




def log_convert_format(log_message_date, log_message_guid, log_message_from, log_message_to, log_message_subject,
                       log_message_ip,
                       log_message_host, log_message_protocol, log_message_tls_version, log_message_disposition,
                       log_message_score_overall, log_message_triggeredClassifier,
                       log_message_quarantine_rule, log_message_quarantine_folder, log_message_quarantine_type,
                       log_message_quarantine_module,
                       log_message_url,log_message_object_status,log_message_object_type,log_message_object_name,log_message_object_md5):
    msg = (log_message_date + "|[prooftpoint]|vmid=" + log_message_guid + "|sender=" + log_message_from +
           "|recipient=" + log_message_to +"|subject=" + log_message_subject + "|sip=" + log_message_ip +
           "|sname=" + log_message_host +"|protoname=" + log_message_protocol + "|version=" + log_message_tls_version +
           "|action=" + log_message_disposition +"|rate=" + log_message_score_overall + "|threatname=" + log_message_triggeredClassifier +
           "|policy=" + log_message_quarantine_rule +"|session=" + log_message_quarantine_folder + "|session_type=" + log_message_quarantine_type +
           "|proccess=" + log_message_quarantine_module+ "|url="+log_message_url+"|status="+log_message_object_status+"|object_type="+log_message_object_type+"|object_name="+log_message_object_name+"|md5="+log_message_object_md5)
    return msg


def get_local_date(str_date):
    str_date_array = str_date.split("+")
    str_date = str_date_array[0]

    # Convert from string to datetime format
    dt_date = datetime.datetime.strptime(str_date, '%Y-%m-%dT%H:%M:%S.%f')

    # Convert date to GMT+7
    local_time = dt_date + datetime.timedelta(hours=-1)

    return str(local_time)


def write_system_log(log_msg):
    try:
        config.get_config()
    except Exception as ex:
        print("Failed to load the configuration")
        print(ex)

    log_path = config.config_system_log_path
    log_file_name = config.config_system_log_name

    # validate if directory exist or not
    #
    #
    if not os.path.isdir(log_path):
        write_system_log('Directory "' + log_path + '" is not found')
        try:
            write_system_log('Creating the Directory event log directory')
            os.mkdir(log_path)
            write_system_log('Directory "' + log_path + '" was successfully created')
        except:
            write_system_log('Creating Directory ' + log_path + 'was failed')
    # validate if file exist or not
    #
    if not os.path.isfile(log_path + "\\" + log_file_name):
        log_file = open(log_path + "\\" + log_file_name, "x")
        log_file = open(log_path + "\\" + log_file_name, "w")
    else:
        log_file = open(log_path + "\\" + log_file_name, "a")

    print(log_msg, file=log_file)
    return

def write_event_log_message(log_msg):
    #Loag the log information
    #
    try:
        config.get_config()
    except:
        print("Failed to load the configuration")

    #set to local variable
    #
    log_path=config.config_event_log_path
    log_file_name=config.config_event_log_name

    # validate if directory exist or not
    #
    #
    if not os.path.isdir(log_path):
        write_system_log('Directory "'+log_path+'" is not found')
        try :
            write_system_log('Creating the Directory event log directory')
            os.mkdir(log_path)
            write_system_log('Directory "'+log_path+'" was successfully created')
        except:
            write_system_log('Creating Directory ' + log_path + 'was failed')
    #validate if file exist or not
    #
    if not os.path.isfile(log_path + "\\" + log_file_name):
        log_file = open(log_path + "\\" + log_file_name, "x")
        log_file = open(log_path + "\\" + log_file_name, "w")
    else:
        log_file = open(log_path + "\\" + log_file_name, "a")


    print(log_msg, file=log_file)
    return

def get_email_form(str_email):
    result = re.search(r'[\w\-\.]+@([\w-]+)((\.[\w-]+)+|(\.)?)', str_email)

    if result != None:
        str_email=result.group()
    return str_email

def get_local_log(json_log_msg):
    jsonmessage = json_log_msg

    log_message_date = get_local_date(str(jsonmessage["ts"]))
    log_message_guid = str(jsonmessage["guid"])

    try:
        log_message_from = str(jsonmessage["msg"]["normalizedHeader"]["from"])
        #print(get_email_form(log_message_from))

    except:
        try:
            log_message_from = str(jsonmessage["envelope"]["from"])
            #print(get_email_form(log_message_from))
        except:
            log_message_from=''

            pass



    try :
        log_messages_to = jsonmessage["msg"]["normalizedHeader"]["to"]
    except:
        try:
            log_messages_to = jsonmessage["msg"]["normalizedHeader"]["reply-to"]
        except:
            try:
                log_messages_to = jsonmessage["envelope"]["rcpts"]
            except:
                log_messages_to=''
                pass


    try:
        log_message_subject = str(jsonmessage["msg"]["normalizedHeader"]["subject"])
    except:
        log_message_subject = ''
        pass
    log_message_ip = str(jsonmessage["connection"]["ip"])
    try:
        log_message_host = str(jsonmessage["connection"]["host"])
    except:
        log_message_host = ''
    pass

    log_message_protocol = str(jsonmessage["connection"]["protocol"])

    try:
        log_message_tls_version = str(jsonmessage["connection"]["tls"]["inbound"]["version"])
    except:
        log_message_tls_version = ''
        pass

    log_message_disposition = str(jsonmessage["filter"]["disposition"])

    try:
        log_message_quarantine_module = str(jsonmessage["filter"]["quarantine"]["module"])
    except:
        log_message_quarantine_module = ''
        pass
    try:
        log_message_quarantine_folder = str(jsonmessage["filter"]["quarantine"]["folder"])
    except:
        log_message_quarantine_folder = ''
        pass
    try:
        log_message_quarantine_type = str(jsonmessage["filter"]["quarantine"]["type"])
    except:
        log_message_quarantine_type = ''
        pass
    try:
        log_message_quarantine_rule = str(jsonmessage["filter"]["quarantine"]["rule"])
    except:
        log_message_quarantine_rule = ''
        pass

    try:
        log_message_score_overall = str(jsonmessage["filter"]["modules"]["spam"]["scores"]["overall"])
    except:
        log_message_score_overall = ''
        pass

    try:
        log_message_triggeredClassifier = str(jsonmessage["filter"]["modules"]["spam"]["triggeredClassifier"])
    except:
        log_message_triggeredClassifier = ''
        pass

    if (log_message_triggeredClassifier == 'phish') or (log_message_triggeredClassifier == 'malware'):

        log_message_url_msg = jsonmessage.get("msgParts")
        log_message_url=get_url(log_message_url_msg)
    else:
        log_message_url = ''


    #
    # field_filter = jsonmessage.get("filter")
    # actions = field_filter.get("actions")
    # action_dkimv = []
    # action_spf = []
    # action_dmarc = []
    # for action in actions:
    #     isFinal = action.get("isFinal")
    #     module = action.get("module")
    #     if module == "dkimv":
    #         action_dkimv.append(action)
    #     elif module == "spf":
    #         action_spf.append(action)
    #     elif module == "dmarc":
    #         action_dmarc.append(action)
    #     if isFinal:
    #         jsonmessage["final_action"] = action.get("action")
    #         jsonmessage["final_module"] = action.get("module")
    #         jsonmessage["final_rule"] = action.get("rule")
    # jsonmessage["action_dkimv"] = action_dkimv
    # jsonmessage["action_spf"] = action_spf
    # jsonmessage["action_dmarc"] = action_dmarc
    #
    # # isFinal = action.get("isFinal")
    # # log_message_action= jsonmessage["filter"]["actions"]
    # #log_message_action = str(jsonmessage["action_dmarc"]) + " - " + str(jsonmessage["final_action"]) + " - " + str(jsonmessage["final_module"]) + " - " + str(jsonmessage["final_rule"])
    # # print(log_message_triggeredClassifier)


    #extract object value from json messages
    #
    log_message_objects=get_hash_object(jsonmessage.get("msgParts"))
    log_message_object_status=str(log_message_objects[0])
    log_message_object_type = str(log_message_objects[1])
    log_message_object_name = str(log_message_objects[2])
    log_message_object_md5 = str(log_message_objects[3])
    #print(log_message_guid + " >> Status : " + log_message_object_status + " | Name : " + log_message_object_name + " | Ext : " + log_message_object_type+" | md5 : " +log_message_object_md5)



    if len(log_messages_to) == 1:
        if len(re.split(r',', str(log_messages_to))) > 1:
            result=re.split(r',', str(log_messages_to))
            inx=0
            log_messages_to.pop(0)
            for x in result:
                log_messages_to.insert(inx,x)
                inx += 1

        #multi_recepient_single_str = re.split(r',', log_messages_to)
        #for rcpnt in multi_recepient_single_str:
         #   log_message_to = get_email_form(str(rcpnt))

    mk=0

    for recepient in log_messages_to:

        log_message_to=get_email_form(str(recepient))
        log_message_from = get_email_form(log_message_from)
        #print("from : "+ log_message_from +"   >>>>>>>> : " + log_message_to)

        #local_log_msg = ''

        local_log_msg=log_convert_format(log_message_date, log_message_guid, log_message_from, log_message_to, log_message_subject,
                       log_message_ip,
                       log_message_host, log_message_protocol, log_message_tls_version, log_message_disposition,
                       log_message_score_overall, log_message_triggeredClassifier,
                       log_message_quarantine_rule, log_message_quarantine_folder, log_message_quarantine_type,
                       log_message_quarantine_module,log_message_url,log_message_object_status,log_message_object_type,log_message_object_name,log_message_object_md5)
       # print(local_log_msg)
        write_event_log_message(local_log_msg)

    return local_log_msg




write_event_log_message('test jon')