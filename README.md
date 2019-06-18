# AWS Cloud API Readme

## Functionality 

### dynamo-db.py

Parse nmap scan and put items in rows

### update_item_dp.py

Parse nmap scan and update missing items

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