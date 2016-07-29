#!/usr/bin/python
# Ryan Busk
# takes csv and uploads it to specified sql server table
# 7/27/2016

import sys
import os
import pandas
from pandas.io import sql
import sqlalchemy

# check length of input arguments, making sure input is correct
if len(sys.argv) != 6:
    sys.stderr.write("Input should be python script sql_server database table file.csv schema\n")
    sys.exit(1)

sql_server = sys.argv[1]

sql_server_db = sys.argv[2]

sql_table = sys.argv[3]

if os.path.isfile(sys.argv[4]):
    in_file = sys.argv[4]
else:
    sys.stderr.write("File "+sys.argv[4]+" does not exist.\n")
    sys.exit(1)

sql_schema = sys.argv[5]

# make engine to sql server using sqlalchemy
engine = sqlalchemy.create_engine("mssql+pyodbc://%s:%s@%s/%s?driver=ODBC+DRIVER+11+for+SQL+SERVER" % (os.environ.get('SQL_username_temp'), os.environ.get('SQL_Password_temp'), sql_server, sql_server_db))

# connect to sqlalchemy engine
server_conn = engine.connect()

# read csv into pandas df
inputs = pandas.read_csv(in_file, chunksize=10000,index_col=False)

# read dataframe into sql server
for chunk in inputs:
    #chunk.insert(0,index,1)
    chunk.to_sql(sql_table, server_conn, if_exists='append', index=False, schema=sql_schema)

# close server connections
server_conn.close()

