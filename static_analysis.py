import magic
import hashlib
import sys
import pefile
import time
import requests
import os
from py2neo import Graph
import re
import json
import network
from datetime import datetime
import process_behavior
import test_url
import pandas as pd
import numpy as np
import random
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import pickle
error_file_handle=open("/tmp/Malware","w") #opening log file 
debug_log_file=open("/tmp/malware_debug","w")
f=open('/home/zero-gravity/Desktop/report.json', 'r')
report_json = json.load(f)
graph = Graph("localhost:7474", auth=("neo4j", "enter your neo4j password"))
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
def retrieve_file_type():
    m = magic.Magic()
    file_type=str(m.from_file(sys.argv[1]))
    content=open(sys.argv[1],"rb").read()
    md5_hash=hashlib.md5(content).hexdigest()
    sha1_hash=hashlib.sha1(content).hexdigest()
    sha256_hash=hashlib.sha256(content).hexdigest()
    graph.run("MERGE (n:FileType {name:'FileType',file_type:{M},md5:{N},sha1:{N1},sha256:{N2}})",M=file_type,N=md5_hash,N1=sha1_hash,N2=sha256_hash)
    return md5_hash
def import_table(): #gets import table and creates a relationship between the malware a
    pe=pefile.PE(sys.argv[1],fast_load=True)
    pe.parse_data_directories()
    for import_in in pe.DIRECTORY_ENTRY_IMPORT:
        graph.run("MERGE (n:DLL_IMPORTED {name:{N}})",N=str(import_in.dll,'utf-8'))
        graph.run("MATCH (a:FileType),(b:DLL_IMPORTED) MERGE (a)-[r:DLL_IMPORTED]->(b)")
        for imp in import_in.imports:
            try:
                graph.run("MERGE (n:IMPORTED_FUNCTIONS {func_name:{N}})",N=str(imp.name,'utf-8'))
                graph.run("MATCH (a:DLL_IMPORTED),(b:IMPORTED_FUNCTIONS) WHERE a.name={N} MERGE (a)-[r:IMPORTS]->(b)",N=str(import_in.dll,'utf-8'))
            except TypeError:
                graph.run("MERGE (n:IMPORTED_FUNCTIONS {func_name:{N}})",N=str(imp.name))
                graph.run("MATCH (a:DLL_IMPORTED),(b:IMPORTED_FUNCTIONS) WHERE a.name={N} MERGE (a)-[r:IMPORTS]->(b)",N=str(import_in.dll))

def get_compilation_time(md5_hash): #gets the compilation time and creates and a node for it .
    pe=pefile.PE(sys.argv[1])
    timestamp = pe.FILE_HEADER.TimeDateStamp
    compilation_time=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(timestamp))
    graph.run("MERGE (n:compliedat {compilation_time:{N}})",N=compilation_time)
    graph.run("MATCH (a:FileType),(b:compliedat) MERGE (a)-[r:COMPILED_AT]->(b)")
def get_export_table(md5_hash): #gets the export table and create a relationship
    pe=pefile.PE(sys.argv[1])
    if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            graph.run("MERGE (n:EXPORT_TABLE) {exp_name:{N}})",N=str(exp.name,'utf-8'))
            graph.run("MATCH (a:FileType),(b:EXPORT_TABLE) WHERE a.md5={N} MERGE (a)-[r:EXPORTS]->(b)",N=md5_hash)
def virus_total(): #queries the virus total 
    params = {'apikey': '2b27a0aa957f95cc540219f81364a8be96d1414ec2b6b57fc50e0f87900787ab'}
    files = {'file': ('', open('/home/zero-gravity/Downloads/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe', 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    json_response = response.json()
    return json_response['md5']
def get_file_report(md5_hash): #gets the file report from the hash believing hash is already there in the db
    print(md5_hash)
    params = {'apikey': '2b27a0aa957f95cc540219f81364a8be96d1414ec2b6b57fc50e0f87900787ab', 'resource': md5_hash}
    headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  My Python requests library example client or username"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
    params=params, headers=headers)
    json_response = response.json()
    detected=json_response['scans']['Microsoft']['detected']
    if detected:
        result=str(json_response['scans']['Microsoft']['result'])
        graph.run("MERGE (n:virustotal {detected_as: {N}})",N=result)
        graph.run("MATCH (a:FileType),(b:virustotal) WHERE a.md5={N} MERGE (a)-[r:IS_DETECTED]->(b)",N=md5_hash)
    else:
        graph.run("MERGE (n:virustotal {detected:'No'})")
        graph.run("MATCH (a:FileType),(b:virustotal) WHERE a.md5={N} MERGE (a)-[r:IS_DETECTED]->(b)",N=md5_hash)
def extract_file_signature(md5_hash):
    totsize = os.path.getsize(sys.argv[1])
    pe = pefile.PE(sys.argv[1], fast_load = True)
    pe.parse_data_directories( directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY'] ] )

    sigoff = 0
    siglen = 0
    for s in pe.__structures__:
        if s.name == 'IMAGE_DIRECTORY_ENTRY_SECURITY':
            sigoff = s.VirtualAddress
            siglen = s.Size
    if siglen == 0:
        print('Error: source file not signed')
        graph.run("MERGE (n:FileSigned { error:'File Not Signed'})")
        graph.run("MATCH (a:FileType),(b:FileSigned) WHERE a.md5={N} MERGE (a)-[r:NOT_SIGNED]->(b)",N=md5_hash)
        return
    signature = pe.write()[sigoff+8:]
    os.system("touch /tmp/SignatureFile.der")
    SignatureFile="/tmp/SignatureFile.der"
    if SignatureFile:
        f = open(SignatureFile, 'wb+')
        f.write(signature)
        f.close()
    print("Creating text file for the .der file")
    os.system("openssl pkcs7 -inform DER -print_certs -text -in /tmp/SignatureFile.der > /tmp/SignatureFile.txt")
    f=open("/tmp/SignatureFile.txt")
    #graph.run("MERGE (n:DigitalSig { md5_hash:{N}}",N=md5_hash)
    data=f.readline()
    before_date=[]
    after_date=[]
    authority_chain=[]
    while data:
        if(re.search(r"Not Before:",data)):
            z_before=re.findall(r"Not Before: (.+)\n",data)
            before_date.append(str(z_before[0]))
        elif(re.search(r"Not After",data)):
            z_after=re.findall(r"Not After : (.+)\n",data)
            after_date.append(z_after[0])
        elif(re.search(r"Issuer.+CN=.+",data)):
            z=re.findall(r"CN=(.+)\n",data)
            authority_chain.append(z[0])
        data=f.readline()
    if(len(authority_chain)==len(after_date) and len(after_date)==len(before_date)):
        index=len(authority_chain)
        for i in range(0,index):
            graph.run("MERGE (n:SIGNED_BY {before_date:{N},after_date:{M},CN:{N1}})",N=before_date[i],M=after_date[i],N1=authority_chain[i])
            graph.run("MATCH (a:FileType),(b:SIGNED_BY) WHERE a.md5={N} MERGE (a)-[r:SIGNED]->(b)",N=md5_hash)
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

print("Running the script")
print("Analyzing the malware ",sys.argv[1])
md5_hash=retrieve_file_type()
import_table()
get_compilation_time(md5_hash)
get_export_table(md5_hash)
#md5_hash=virus_total()
get_file_report(md5_hash)
extract_file_signature(md5_hash)
get_http(md5_hash) #call to network module to get all the urls and add to the graph 
network.create_network(md5_hash)
process_behavior.get_peid_signature(md5_hash)
process_behavior.dropped_files(md5_hash)
process_behavior.behaviour_Process(md5_hash)  #calls the function in the process_behavior 
process_behavior.check_tor_services(md5_hash) #checks for the tor services 