#!/usr/bin/python
# Ryan Busk
# Takes two files and a databse, merges them, and returns the difference for xml
# 7/29/2016

import sqlite3 as lite
import sys
import os
import pandas
from pandas.io import sql
from datetime import datetime


def get_fixed_date():
    now = datetime.now()
    if now.day >= 15:
        day = 1
        if now.month is 12:
            month = 1
            year = now.year+1
        else:
            month = now.month+1
            year = now.year
    else:
        day = 15
        month = now.month
        year = now.year
    return str(month)+"/"+str(day)+"/"+str(year)

# check length of input arguments, making sure input is correct
if len(sys.argv) != 6:
    sys.stderr.write("Input should be python script current_vuln.csv last_report.csv sql_database current_export.csv fixed_export.csv\n")
    sys.exit(1)

# check if files exist
if os.path.isfile(sys.argv[1]):
    this_week = sys.argv[1]
else:
    sys.stderr.write("File "+sys.argv[1]+" does not exist.\n")
    sys.exit(1)

if os.path.isfile(sys.argv[2]):
    last_week = sys.argv[2]
else:
    sys.stderr.write("File "+sys.argv[2]+" does not exist.\n")
    sys.exit(2)

# database does not need to exist before program is run
database = sys.argv[3]

# csv name for export of current vulns
current_export = sys.argv[4]

# csv name for export of fixed vulnerabilities
fixed_export = sys.argv[5]

# connect to sqlite database if it exists, if not, create database
lite_conn = lite.connect(database)

# cursor for sql server
c = lite_conn.cursor()

# drop tables from last reporting period in sqlite db
c.execute('DROP TABLE IF EXISTS this_report')
c.execute('DROP TABLE IF EXISTS last_report')

# read in data from this reporting week ad last reporting week into pandas dataframes
current = pandas.read_csv(this_week, chunksize=10000)
previous = pandas.read_csv(last_week, chunksize=10000)

# load data into sql tables
for chunk in current:
    chunk.to_sql('this_report', lite_conn, if_exists='append', index=False)

for chunk in previous:
    chunk.to_sql('last_report', lite_conn, if_exists='append', index=False)

# clear variables
previous = None
current = None

# find fixed vulns from comparison and read them into pandas dataframe
fixed = sql.read_sql('SELECT * FROM last_report WHERE unique_key NOT IN (SELECT unique_key FROM this_report)', lite_conn)
fixed['fixed_date'] = get_fixed_date()

# read new vulns into new pandas df
new = sql.read_sql('Select * FROM this_report WHERE unique_key NOT IN (SELECT unique_key FROM last_report)', lite_conn)

# read new df to the current_vulns table
new.to_sql('current_vulns', lite_conn, if_exists='append', index=False)

# load fixed vulns to the fixed_vulns sql table in the sqlite server
fixed.to_sql('fixed_vulns', lite_conn, if_exists='append', index=False)

# clear fixed
fixed = None
new = None

# read all of fixed_vulns into df
remediated = sql.read_sql('SELECT * FROM fixed_vulns', lite_conn)

# remove duplicates
remediated.drop_duplicates(keep='first', inplace=True)

# remove fixed vulns table
c.execute('DROP TABLE IF EXISTS fixed_vulns')

# replace table with duplicates removed
remediated.to_sql('fixed_vulns', lite_conn, index=False)

# commit changes to server
lite_conn.commit()

# read all of current_vulns with correct dates into df
total = sql.read_sql('select * FROM current_vulns', lite_conn)

#remove previous reports
try:
    os.remove(current_export)
except OSError:
    pass

try:
    os.remove(fixed_export)
except OSError:
    pass

# export current_vulns to csv
total.to_csv(current_export)

# export remediated to csv
remediated.to_csv(fixed_export)

# close server connections
lite_conn.close()

