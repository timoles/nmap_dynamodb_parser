import boto3
import sys
from datetime import datetime
import json

from libnmap.parser import NmapParser

# Get the table we want to work on
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table("TestTable3")

nmap_report = NmapParser.parse_fromfile('0BBM3XYOWN32GN8A1IEJYQ7YUET2BS6C1TBHMILK.xml')
key = {"Domain": "telekom.de", "Subdomain": "access"}
response = table.get_item(
    Key=key,
    AttributesToGet=[
        'ports-open',
        'ports-scanned',
	],
    ConsistentRead=True,
    ReturnConsumedCapacity='INDEXES',#|'TOTAL'|'NONE',
#    ProjectionExpression='ports-open',
#    ExpressionAttributeNames={
#        'string': 'string'
#    }
)
#print(response)
#x = response["Item"]["ports-open"]
#print(response["Item"]["ports-open"])

# We had these ports open in the DB
open_in_db = response["Item"]["ports-open"]
print(open_in_db)
#  We scanned these ports
scanned_ports = nmap_report.hosts[0].get_ports()
print(scanned_ports)
for k in open_in_db:
	print(k)

# scanned ports
scanned_ports = nmap_report.hosts[0].get_ports()
op = nmap_report.hosts[0].get_open_ports()

sys.exit()

scanned_ports_db = {}
scanned_hosts = nmap_report.hosts
for host in scanned_hosts:
	for hostname in host.hostnames:
		item = {}
		key = {}
		# Primary / Sort-key
		domain = str.join(".", hostname.split(".")[-2:])
		subdomain = str.join(".", hostname.split(".")[:-2])
		key.update({"Domain":domain})
		key.update({"Subdomain":subdomain})
		# Additional data
		item.update({"host_address":host.address})
		item.update({"host_status":{"status":host.status,"date":host.endtime}})
		scanned_ports = host.get_ports()
		scanned_ports_db = {}
		for port in scanned_ports:
			scanned_ports_db.update({str(port[0]): {"proto": str(port[1]), "date": host.endtime}})
		open_ports = host.get_open_ports()
		ports_service = {}
		for port in open_ports:
			ports_service.update({str(port[0]): {"nmap_service_desc": str(nmap_report.hosts[0].get_service(port[0], protocol=port[1])), "date": host.endtime}})
		item.update({"ports_open": ports_service})
		# item.update({"ports-open": {}})  # TODO wrong
		item.update({"scanned_ports": scanned_ports_db})
		#inputData = table.update_item(Item=item)  # TODO mby change to update_item
		#ports_service = {"5000":{}}
		inputData = table.update_item(
										Key=key,
										#UpdateExpression='set #ports_open.#port = :r',
										UpdateExpression='set #ports_open = :r',
									    ExpressionAttributeValues={
									        ':r': {"date":"testdate", "nmap_service_desc":"desc"},
									    },
							        	ExpressionAttributeNames={
							        		"#ports_open":"ports_open",
									    },  
									    ReturnValues="UPDATED_NEW")  # TODO mby change to update_item
		print(inputData)
		sys.exit()  # TODO

# TODO update with new ports
# TODO update with port that previously was open and is now closed

sys.exit()
# dynamoData = boto3.client('dynamodb')#, region_name='us-east-1')

# Put the data in the table
inputData = table.put_item(Item=item)  # TODO mby change to update_item
print(inputData)
sys.exit()


with open("only_domain_names_no_buckets.lst", 'r') as the_file:
	for domain in the_file:
		domain = domain.rstrip()
		if domain:
			print(domain)
			#response = client.update_item(
			response = client.put_item(
				    TableName='Domain-List',
				    Item= {
   "domain-name": {
     "S": "01aa-timo.de"
   },
   "partition-key": {
     "S": "DNS-Scan"
   },
 },
			    UpdateExpression='SET ports-open = :val1',
    ExpressionAttributeValues={
        ':val1': ports_service
    }

			)
			print(response)
			sys.exit(0)


# partition-key(string) | domain-name(string) | first-seen(date/string) | last-seen(date/string) | ip-addr(string) | ports-open(List) | ports-filtered(List) | ports-closed(List) | URLs-scanned(Map) | Headers(Map) |
# {
#   "domain-name": {
#     "S": "00aa-timo.de"
#   },
#   "First-seen": {
#     "S": "2019-06-12"
#   },
#   "Header": {
#     "M": {
#       "/evil.php": {
#         "S": "Server: nginx"
#       },
#       "/index.php": {
#         "S": "X-Security: on"
#       }
#     }
#   },
#   "ip-addr": {
#     "S": "127.0.0.1"
#   },
#   "Last-seen": {
#     "S": "2019-06-12"
#   },
#   "partition-key": {
#     "S": "DNS-Scan"
#   },
#   "ports-closed": {
#     "M": {
#       "8080": {
#         "S": "8080/open/tcp//http//Microsoft IIS httpd 8.5/"
#       },
#       "8443": {
#         "S": "80/open/tcp//http-proxy//F5 BIG-IP load balancer http proxy/"
#       }
#     }
#   },
#   "ports-filtered": {
#     "M": {
#       "22": {
#         "S": "22/filtered/...."
#       }
#     }
#   },
#   "ports-open": {
#     "M": {
#       "80": {
#         "S": "80/open/tcp/..."
#       },
#       "443": {
#         "S": "443/open/tcp/..."
#       }
#     }
#   },
#   "Url-scanned": {
#     "M": {
#       "/evil.php": {
#         "S": "404"
#       },
#       "/index.php": {
#         "S": "200 OK"
#       }
#     }
#   }
# }
