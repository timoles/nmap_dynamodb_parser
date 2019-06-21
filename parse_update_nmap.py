import boto3
import sys
from libnmap.parser import NmapParser


def db_update_ports(item_key, updated_ports, scanned_ports, nmap_host):
        ipv4 = ""
        ipv6 = ""
        if host.ipv4:
            ipv4 = host.ipv4
        else:
            ipv4 = "None"
        if host.ipv6:
            ipv6 = host.ipv6
        else:
            ipv6 = "None"

        inputData = table.update_item(
                           Key=item_key,
                           # UpdateExpression='set #ports_open.#port = :r',
                           UpdateExpression='set #ports_open = :r, #ports_scanned = :c, #addr_ipv4 = :b, #addr_ipv6 = :d, #host_status = :a, #scantime = :t',
                           ExpressionAttributeValues={
                               ':r': updated_ports,
                               ':c': scanned_ports,
                               ':a': host.status,
                               ':b': ipv4,
                               ':d': ipv6,
                               ':t': host.endtime,
                           },
                           ExpressionAttributeNames={
                               "#ports_open":"ports_open",
                               "#ports_scanned":"ports_scanned",
                               "#host_status": "host_status",
                               "#addr_ipv4": "addr_ipv4",
                               "#addr_ipv6": "addr_ipv6",
                               "#scantime": "scantime",
                           },
                           ReturnValues="UPDATED_NEW")  # TODO mby change to update_item
        return inputData


def db_get_open_ports(db_key):
    response = table.get_item(
        Key=key,
        AttributesToGet=[
            'ports_open',
            # 'ports_scanned',
        ],
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',  # 'INDEXES',#|'TOTAL'|'NONE',
    )
    return response


def db_get_scanned_ports(db_key):
    response = table.get_item(
        Key=key,
        AttributesToGet=[
            #'ports_open',
            'ports_scanned',
        ],
        ConsistentRead=True,
        ReturnConsumedCapacity='TOTAL',  # 'INDEXES',#|'TOTAL'|'NONE',
    )
    return response


def nmap_get_subdomain(nmap_hostname):
    subdomain = str.join(".", nmap_hostname.split(".")[:-2])
    return subdomain


def nmap_get_domain(nmap_hostname):
    domain = str.join(".", nmap_hostname.split(".")[-2:])
    return domain


def scanned_ports_db_update(scanned_ports_db_dict, nmap_port, nmap_hostname):
    scanned_ports_db_dict.update({str(nmap_port[0]): {"proto": str(nmap_port[1]), "date": nmap_hostname.endtime}})


def open_in_db_new_update_new_keypair(new_open_ports_dict, nmap_host, nmap_port):
    new_open_ports_dict.update({str(nmap_port[0]): {"nmap_service_desc": str(nmap_host.get_service(nmap_port[0], protocol=nmap_port[1])), "date": nmap_host.endtime, "proto": nmap_port[1]}})


def get_previous_open_ports(db_key):
    found_open_ports = []
    for k, v in db_get_open_ports(key)["Item"]["ports_open"].items():
                placeholder = (int(k), v["proto"])
                found_open_ports.append(placeholder)
    return found_open_ports


# Get the table we want to work on
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table("TestTable4")

nmap_report_parsed = NmapParser.parse_fromfile('0BBM3XYOWN32GN8A1IEJYQ7YUET2BS6C1TBHMILK.xml')


nmap_scanned_hosts = nmap_report_parsed.hosts
for host in nmap_scanned_hosts:
    for hostname in host.hostnames:
        print("Working on hostname: {}".format(hostname))
        item = {}
        key = {}
        new_open_ports = {}

        # Get Primary / Sort-key From the current nmap host
        domain = nmap_get_domain(hostname)
        subdomain = nmap_get_subdomain(hostname)
        key.update({"Domain": domain})
        key.update({"Subdomain": subdomain})

        # Update metadata for the current host (scantime/ addr/ host status)
        nmap_scanned_ports = host.get_ports()

        # Get all newly scanned ports
        scanned_ports = host.get_ports()
        try:
            # Copy all previously found ports in the new port column
            new_open_ports = db_get_open_ports(key)["Item"]["ports_open"]
            # Remove all dict entries which will recieve an update through the new nmap scan
            for x in scanned_ports:
                port = str(x[0])
                proto = x[1]
                try:
                    # Check if we have a port in the nmap scan which is also is in the database
                    if new_open_ports[port]["proto"] == proto:
                        # Delete the port that needs updating
                        del(new_open_ports[port])
                except KeyError:
                    # Key does not exist, continue
                    pass
        except KeyError:
            # Didn't find any previously found open ports
            pass

        # Now we need to insert the nmap scan open ports into our new_open_ports
        for open_port in host.get_open_ports():
            open_in_db_new_update_new_keypair(new_open_ports, host, open_port)

        # Make column with all scanned ports
        # Get all the previously scanned ports from the databse
        all_scanned_ports_column = db_get_scanned_ports(key)["Item"]["ports_scanned"]
        # Update the previously scanned ports with the nmap scan

        for port in nmap_scanned_ports:
            scanned_ports_db_update(all_scanned_ports_column, port, host)

        # Write the updates to the database
        inputData = db_update_ports(key, new_open_ports, all_scanned_ports_column, host)
