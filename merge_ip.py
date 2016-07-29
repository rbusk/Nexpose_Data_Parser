#!/usr/bin/python
# Ryan Busk
# 7/29/2016
import pandas as pd
import sys
import os


def left_out_join(input_arg):
    # check if proper number of input arguments
    if len(input_arg) is not 3:
        sys.stderr.write("Input shold be ./script node.csv vuln.csv\n")
        sys.exit()

    # check if first file exists
    if os.path.isfile(input_arg[0]):
        in_node = input_arg[0]
    else:
        sys.stderr.write("File "+input_arg[0]+" does not exist.\n")
        sys.exit()

    # check if second file exists
    if os.path.isfile(input_arg[1]):
        in_vuln = input_arg[1]
    else:
        sys.stderr.write("File "+input_arg[1]+" does not exist.\n")
        sys.exit()

    # remove file extension of first file
    no_extension = os.path.splitext(in_node)[0]

    # name outfile
    out_file = no_extension + "_merged.csv"

    # delete outfile if it exists already because we are appending data
    try:
        os.remove(out_file)
    except OSError:
        pass

    # read files into dataframe
    vuln_df = pd.read_csv(in_vuln)
    nodes_df = pd.read_csv(in_node, chunksize=10000)
    owners_df = pd.read_csv(input_arg[2], low_memory=False)

    # flag to see if header needs to be written to outfile
    header = 0

    # iterate through chunks of dataframe from the node csv
    for chunk in nodes_df:
        # left outer join with the vulnerability data
        chunk = pd.merge(left=chunk, right=vuln_df, how='left', left_on='cert', right_on='cert')
        # left out join with the owners data
        chunk = pd.merge(left=chunk, right=owners_df, how='left', left_on='dest_ip', right_on='IP_Address')
        # check if header needs to be written
        if header is 0:
            # write to csv, change header flag
            chunk.to_csv(out_file, mode='a', index=None)
            header = 1
        else:
            # write to csv with no header
            chunk.to_csv(out_file, mode='a', index=None, header=None)

if __name__ == "__main__":
    left_out_join([sys.argv[1], sys.argv[2], sys.argv[3]])
