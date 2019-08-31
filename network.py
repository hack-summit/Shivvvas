import json
from py2neo import Graph
from datetime import datetime
import re
import test_url
import pandas as pd
import numpy as np
import random
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pickle
graph = Graph("localhost:7474", auth=("neo4j", "vasuptm123"))
error_file_handle=open("/tmp/Malware","w") #opening log file 
debug_log_file=open("/tmp/malware_debug","w")
f=open('/home/zero-gravity/Desktop/report.json', 'r')
report_json = json.load(f)
def sanitization(web):                      # tokenizing method
    web = web.lower()
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')            # removing slash to get token
        slash_token = []
        for j in range(0,len(raw1)):
            raw2 = str(raw1[j]).split('.')  # removing dot to get the tokenS
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token # all tokens
    token = list(set(dot_token_slash))      # to remove same words  
    if 'com' in token:
        token.remove('com')                 # remove com
    return token

def check_malicious_urls(url):
    urls=[]
    urls.append(url)
    file = "pickel_model.pkl"
    with open(file, 'rb') as f1:  
        lgr = pickle.load(f1)
    f1.close()
    file = "pickel_vector.pkl"
    with open(file, 'rb') as f2:
        vectorizer = pickle.load(f2)
    f2.close()
    vectorizer = vectorizer
    x = vectorizer.transform(urls)
    #score = lgr.score(x_test, y_test)
    y_predict = lgr.predict(x)
    return y_predict
def create_network(md5_hash):
        #look at the network field
        try:
            print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] Creating a node under the label HOSTS")
            debug_log_file.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO]s Creating a node with label HOSTS")
            graph.run("MERGE (n:HOSTS { node : 'Hosts'})")
            for hosts in report_json['network']['hosts']:
                print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] Host ip address found , creating a node:"+str(hosts))
                debug_log_file.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] Host ip address found , creating a node:"+str(hosts))
                graph.run("MERGE (n:HOSTS_IP { ip:{N}})",N=hosts)
                print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] Creating a relationship for ip address:"+str(hosts))
                debug_log_file.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] Creating a relationship for ip address:"+str(hosts))
                graph.run("MATCH (a:HOSTS),(b:HOSTS_IP) MERGE (a)-[r:TO_WHICH_HOST]->(b)")
            graph.run("MATCH (a:FileType),(b:HOSTS) WHERE a.md5={N} MERGE (a)-[r:Network_Hosts]->(b)",N=md5_hash) 
        except KeyError:
            print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [ERROR] Key Hosts or network key not Found")
            log_file_handle.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [ERROR] Key Hosts or network key not Found")
        except:
          print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [ERROR] Connection to neo4j refused")
          error_file_handle.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [ERROR] Connection to neo4j refused")
def get_http(md5_hash):
    try:
        graph.run("MERGE (n:HTTP {node :'HTTP(s)_HOST'})")
        if report_json['network']['http'] is None:
            print("No HTTP host found")
        else:
            for uri in report_json['network']['http']:
                print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] HTTP Method and the URL found , creating a node:"+str(uri['method'])+" "+str(uri['uri']))
                debug_log_file.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] HTTP Method and the URL found , creating a node:"+str(uri['method'])+" "+str(uri['uri']))
                return_value=check_malicious_urls(uri['uri'])
                if return_value[0]=='bad':
                    #graph.run("MERGE (n:HTTP_URL")
                    graph.run("MERGE (n:HTTP_URL {url:{N},method:{N1}})",N=str(uri['uri']),N1=str(uri['method']))
                    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] Creating a relationship ")
                    debug_log_file.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [INFO] Creating a relationship for the url")
                    graph.run("MATCH (a:HTTP),(b:HTTP_URL) MERGE (a)-[r:URL_ACCESSED]->(b)")
                    graph.run("MATCH (a:FileType),(b:HTTP) where a.md5={N} MERGE (a)-[r:HTTPS_HTTP_Connection]->(b)",N=md5_hash)
                else:
                    print("Seems Like URL is good not adding to the relationship")
    except KeyError:
        print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [ERROR] HTTP Key not found")
        log_file_handle.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" HTTP Key not found")

if __name__=="__main__":
    print("Running as main")
    exit(0)
