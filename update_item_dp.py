import boto3
import sys
from datetime import datetime
import json
import operator
from libnmap.parser import NmapParser


def db_update_ports(item_key, updated_ports):
        inputData = table.update_item(
                           Key=item_key,
                           #UpdateExpression='set #ports_open.#port = :r',
                           UpdateExpression='set #ports_open = :r',
                           ExpressionAttributeValues={
                               ':r': updated_ports,
                           },
                           ExpressionAttributeNames={
                               "#ports_open":"ports_open",
                           },  
                           ReturnValues="UPDATED_NEW")  # TODO mby change to update_item
        return inputData


def db_get_open_ports(db_key):
    response = table.get_item(
    Key=key,
    AttributesToGet=[
        'ports_open',
        #'ports_scanned',
    ],
    ConsistentRead=True,
    ReturnConsumedCapacity='INDEXES',#|'TOTAL'|'NONE',
    )
    return response


def nmap_get_subdomain(nmap_hostname):
    subdomain = str.join(".", nmap_hostname.split(".")[:-2])
    return subdomain


def nmap_get_domain(nmap_hostname):
    domain = str.join(".", nmap_hostname.split(".")[-2:])
    return domain


def scanned_ports_db_update(scanned_ports_db_dict, nmap_port, nmap_hostname):
    scanned_ports_db_dict.update({str(nmap_port[0]): {"proto": str(nmap_port[1]), "date": nmap_host.endtime}})


def open_in_db_new_update_new_keypair(new_open_ports_dict, nmap_host, nmap_port):
    new_open_ports_dict.update({str(nmap_port[0]): {"nmap_service_desc": str(nmap_host.get_service(port[0], protocol=nmap_port[1])), "date": nmap_host.endtime, "proto": nmap_port[1]}})


xy = {}
xy.update({"1": "1.1"})
print(type(xy))
sys.exit()
# Get the table we want to work on
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table("TestTable4")

nmap_report_parsed = NmapParser.parse_fromfile('0BBM3XYOWN32GN8A1IEJYQ7YUET2BS6C1TBHMILK.xml')

scanned_ports_db = {}
scanned_hosts = nmap_report_parsed.hosts
for host in scanned_hosts:
    for hostname in host.hostnames:
        item = {}
        key = {}
        # Primary / Sort-key
        # domain = str.join(".", hostname.split(".")[-2:])
        domain = nmap_get_domain(hostname)
        # subdomain = str.join(".", hostname.split(".")[:-2])
        subdomain = nmap_get_subdomain(hostname)
        key.update({"Domain":domain})
        key.update({"Subdomain":subdomain})
        # Additional data
        item.update({"host_address":host.address})
        item.update({"host_status":{"status":host.status,"date":host.endtime}})
        scanned_ports = host.get_ports()
        response = db_get_open_ports(key)
        open_in_db = response["Item"]["ports_open"]
        open_db_ports = []
        for k, v in open_in_db.items():
            placeholder = (int(k), v["proto"])
            open_db_ports.append(placeholder)

        # All ports remaining in x can stay unchanged in the db. The rest was re-scanned and recieves an update (an is potentially not in open anymore)
        # TODO prevent older scans to be imported
        x = list(set(open_db_ports) - set(scanned_ports))
        open_in_db_new = {}
        for i in x:
            i = str(i[0])
            open_in_db_new[i] = open_in_db[i]

        scanned_ports_db = {}
        for port in scanned_ports:
            # scanned_ports_db.update({str(port[0]): {"proto": str(port[1]), "date": host.endtime}})
            scanned_ports_db_update(scanned_ports_db, port, host)
        open_ports = host.get_open_ports()
        ports_service = {}
        for port in open_ports:
            # open_in_db_new.update({str(port[0]): {"nmap_service_desc": str(nmap_report_parsed.hosts[0].get_service(port[0], protocol=port[1])), "date": host.endtime, "proto": port[1]}})
            open_in_db_new_update_new_keypair(open_in_db_new, host, port)
        # We copied all scanned ports from the nmap scan, now we need to copy the old ports we didn't rescan
        for k, v in open_in_db.items():
            try:
                if (open_in_db_new[k]["proto"] == v["proto"]):
                    pass  # Do nothing, we inserted this already
                else:  # We have the port re-scanned, but with another protocol as earlier, so copy the old one!
                    open_in_db_new.update({k, v})
            except KeyError:  # We got a key error because the port was not rescanned and is therefore not in the new dataset. Include it!
                open_in_db_new.update({k, v})

        item.update({"scanned_ports": scanned_ports_db})
        inputData = db_update_ports(key, open_in_db_new)
