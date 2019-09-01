import json 
from py2neo import Graph
from datetime import datetime
import re
graph = Graph("localhost:7474", auth=("neo4j", "enter your password"))
f=open('/home/zero-gravity/Desktop/report.json', 'r')
report_json = json.load(f)
def get_peid_signature(md5_hash):
	if report_json['static']['peid_signatures'] is None:
		print("Peid signature not detected")
	else:
		graph.run("MERGE (n:PACKER_STATIC {name:{N},md5_hash:{M}})",N=str(report_json['static']['peid_signatures'][0]),M=md5_hash)
		graph.run("MATCH (a:FileType),(b:PACKER_STATIC) where a.md5={N} MERGE (a)-[r:PACKER_INDENTIFIED]->(b)",N=md5_hash)
def dropped_files(md5_hash): #Check for yara section (To be done later)
	if report_json['dropped'] is None:
		print("No files dropped")
	else:
		graph.run("MERGE (n:DROPPED_FILES {name:'DROPPED FILES',md5:{N}})",N=md5_hash)
		graph.run("MATCH (a:DROPPED_FILES),(b:FileType) where b.md5={N} MERGE (a)-[r:DROPPED_FILE_SECTION]->(b)",N=md5_hash)
		for i in report_json['dropped']:
			graph.run("MERGE (n:DROPPED_FILES_NAME {name:{N},md5_hash:{M},file_path:{N1},md5_parent:{M1}})",N=str(i['name']),M=i['md5'],N1=i['path'],M1=md5_hash)
			graph.run("MATCH (a:DROPPED_FILES),(b:DROPPED_FILES_NAME) WHERE a.md5={N} MERGE (a)-[r:DROPPED_FILE]->(b)",N=md5_hash)
def behaviour_Process(md5_hash):
	#print(report_json['behavior'])
	graph.run("MERGE (n:PROCESS {name:'PROCESS_EXECUTED',md5:{N}})",N=md5_hash)
	graph.run("MATCH (a:FileType),(b:PROCESS) where a.md5=b.md5 MERGE (a)-[r:PROCESS_EXECUTED]->(b)")
	if report_json['behavior']['generic'] is None:
		print(datetime.now().strftime('%Y-%m-%d %H:%M:%S')+" [DEBUG] generic key not found")
		graph.run("MATCH (n:PROCESS) WHERE n.md5={N} SET n.Process_count=0",N=md)
	else:
		for i in report_json['behavior']['generic']:
			graph.run("MERGE (n:PROCESS_NAME {process_name:{N},pid:{N1},process_path:{N2},md5:{M1}})",N=i['process_name'],N1=i['pid'],N2=i['process_path'],M1=md5_hash)
			graph.run("MATCH (a:PROCESS_NAME),(b:PROCESS) where a.md5=b.md5 MERGE (a)-[r:PROCESS_SPAWNED]->(b)")
			try:
				for registryk in i["summary"]["regkey_written"]:
					print(registryk)
					graph.run("MERGE (n:REGKEY {reg_key:{N},md5:{N1}})",N=registryk,N1=md5_hash)
					graph.run("MATCH (a:PROCESS_NAME),(b:REGKEY) WHERE a.process_name={N} MERGE (a)-[r:REGKEY_WRITTEN]->(b)",N=i['process_name'])
			except:
				print("No reg Key is regkey_written") #add log feature

def check_tor_services(md5_hash):
	flag=0;
	for i in report_json['behavior']['generic']:
		try:
			for j in i['summary']['file_created']:
				if re.search("tor\.exe",j):
					print(i['process_name'])
					print("Tor.exe is created or dropped")
					flag=1
					break
				else:
					flag=0
		except:
			print("Not found")
		if(flag==1):
			break
	if flag==0:
		print("Print Malware probably is not using TOR networking")
		graph.run("MERGE (n:TOR {isTorUsed:'NO',md5:{N}})",N=md5_hash)
	else:
		graph.run("MERGE (n:TOR {isTorUsed:'YES',md5:{N}})",N=md5_hash)
	graph.run("MATCH (a:FileType),(b:TOR) where a.md5=b.md5 MERGE (a)-[r:IsTorUsed]->(b)")

if __name__=="__main__":
	get_peid_signature("84c82835a5d21bbcf75a61706d8ab549")
	dropped_files("84c82835a5d21bbcf75a61706d8ab549")
	behaviour_Process("84c82835a5d21bbcf75a61706d8ab549")
	#print(report_json['behavior']['summary'])
	check_tor_services("84c82835a5d21bbcf75a61706d8ab549")