import inspect
import json
import os.path
from log_proccessing import *
script_path=os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
log_path=script_path+"\logs"
#log_path_file=log_path+"\mnt1_log_sample.log"
log_path_file=log_path+"\log_sample_phising.log"
#log_path_file=log_path+"\\threat_log.log"
jml=0
f=open(log_path_file,'r')

for i in f:
    jml=jml+1
    if i == '\n':
        continue
    else:
        jsonmessage=json.loads(i)
        get_local_log(jsonmessage)
