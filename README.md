# AWS Cloud API Readme

## Usage

```bash
# Init aws credentials
aws configure

python3 parse_update_nmap.py
```

## Functionality 

### parse_update_nmap.py

Parse nmap scan and update the results with a dynamodb aws database

## Databases

### Table 1

Saves all scanned hostnames. Saves mostly Port-data for scanned hosts

PrimaryKey, SortKey: Domain, Subdomain (e.g. timo.de, www)

### Table 2

Saves data for scanned paths on hosts (seperated to Table 1 in order to reduce scan dataset for regular port searches) such as: checks if paths exist, header for existing paths, site content of paths

PrimaryKey, SortKey: URL/IP, Path (e.g. www.timo.de, /backups/index.html)

Other columns: Date, HttpCode, Headers, HTTPS, ResponseBody

## TODO

* Find out how to get currently running fleets
