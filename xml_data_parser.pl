#!/usr/bin/perl
##Ryan Busk
# Script to converty Nexspose XML to JSON/CSV
# 7/29/2016
use strict;
use warnings;
use XML::Hash;
use JSON;
use IO::Handle;
use Data::Dumper;

#get current date and format
#$line =~ s/($year)($month)($day)T($hour)($minute)($second)($ms)/$1-$2-$3 $4:$5:$6.$7/g;

#get date in correct format
my ($c_month,$c_day,$c_year) = get_date();
my $export_date = $c_month.'/'.$c_day.'/'.$c_year;
my $r_month;
my $r_day;
my $r_year;

#get next report date
if ($c_day >= 15) {
	$r_day = 1;
	if ($c_month == 12) {
		$r_month = 1;
		$r_year = $c_year+1;
	} else {
		$r_month = $c_month+1;
		$r_year = $c_year;
	}
} else {
	$r_day = 15;
	$r_month = $c_month;
	$r_year = $c_year;
}
my $report_date = $r_month.'/'.$r_day.'/'.$r_year;

print "$export_date\n$report_date\n";
#get number of input arguments
my $ARGC = scalar @ARGV;

#input variables
my $filename;
my $file_number;
my $file_type;
my $vuln_status;

#pull filename from input
if ($ARGC == 4) {
	#check if file exists
	if (-e $ARGV[0]){
		$filename = $ARGV[0];
	} else {
		die "$ARGV[0] does not exist";
	}
	#check wanted filetype. quit if incorrect
	if ($ARGV[1] eq 'json' || $ARGV[1] eq 'csv' || $ARGV[1] eq 'both'){
		$file_type = $ARGV[1];
	} else {
		die "Input should be ./node_trapper.pl 'file'.xml [json|csv|both] [single|mult|both] [vuln_on|vuln_off]\n./node_trapper.pl file.xml all";
	}
	#check number of files wanted. quit if incorrect
	if ($ARGV[2] eq 'single' || $ARGV[2] eq 'mult' || $ARGV[2] eq 'both'){
		$file_number = $ARGV[2];
	} else {
		die "Input should be ./node_trapper.pl 'file'.xml [json|csv|both] [single|mult|both] [vuln_on|vuln_off]\n./node_trapper.pl file.xml all";
	}
	#check if vulnerabilities should be outputted
	if ($ARGV[3] eq 'vuln_on' || $ARGV[3] eq 'vuln_off'){
		$vuln_status = $ARGV[3];
	} else {
		die "Input should be ./node_trapper.pl 'file'.xml [json|csv|both] [single|mult|both] [vuln_on|vuln_off]\n./node_trapper.pl file.xml all";
	}
#if user inputs all. Everything will be run. Die if incorrect input
} elsif ($ARGC == 2) {
	$filename = $ARGV[0];
	if ($ARGV[1] eq 'all') {
		$file_type = 'both';
		$file_number = 'both';	
		$vuln_status = 'vuln_on';
	}
}else {
	die "Input should be ./node_trapper.pl 'file'.xml [json|csv|both] [single|mult|both] [vuln_on|vuln_off]\n./node_trapper.pl file.xml all";
}

#XML2HASH Converter Object
my $XML2HASH = XML::Hash->new();

#Get name of file without extension
(my $console = $filename) =~ s/\.[^.]+$//;

##CSV HEADERS
#vulnerabilities
my $vuln_header = "cert,vuln_title,cvss_score,cvss_vector,severity,PCI_severity,exploit_count,lowest_exploit_skill,published,added,modified,vuln_risk_score,vuln_custom_risk,export_date,days_to_fix,report_date,due_date\n";
#Nodes
my $node_header = "device_id,site_name,node_risk_score,console,dest_host,dest_full_name,dest_ip,dest_address,scan_id,cert,vulnerable_since,PCI_compliance_status,unique_key,node_custom_risk\n";


#open csv and for vulnerabilities if user inputs 
my $vuln_csv;
my $vuln_json;
if ($vuln_status eq 'vuln_on'){
	open($vuln_json,'>',$console.'_vuln.json');
	open($vuln_csv,'>',$console.'_vuln.csv');
	#print csv header for vulnerabilities
	print $vuln_csv $vuln_header;
}

my $json_of;
my $csv_of;
my $out_csv_file;
my $out_json_file;
#open out file if single file output is selected
#This file is the filename with the specifies filetype form the command line
if ($file_number eq 'single' || $file_number eq 'both') {
	if ($file_type eq 'csv' || $file_type eq 'both') {
		$out_csv_file = $console.'.csv';
		open($csv_of,'>',$out_csv_file);
		print $csv_of $node_header;
	}
	if ($file_type eq 'json' || $file_type eq 'both') {
		$out_json_file = $console.'.json';
		open($json_of,'>',$out_json_file);
	}
}
#regex variables for changing timestamp
my $year = "[0-9][0-9][0-9][0-9]";
my $month = "[0|1][0-9]";
my $day = "[0-3][0-9]";
my $hour = "[0-2][0-9]";
my $minute = "[0-9][0-9]";
my $second = "[0-9][0-9]";
my $ms = "[0-9][0-9][0-9]";

#open file to parse
open(my $FILE, $filename) or die "Cant' open $filename: $!";


#variables for finding node segment
my $string = '[a-z|A-Z|0-9|_|\-|.|,| |:|\(|\)|\\|]*';
my $in_section = 0;
my @data;
my @nodes = [];
my $line_number = 0;


#This while loop scans through the file line by line storing node and vulnerability sections into data and then processing on them. 
#This has to be done because we are processing files that are too big to store all into memory. 
while(my $line = <$FILE>) {
	#change timestamp to a readable timestamp
	$line =~ s/($year)($month)($day)T($hour)($minute)($second)($ms)/$1-$2-$3 $4:$5:$6.$7/g;
	if ($line =~ /<node .*>/) {
		#push data into line if inside node segment
		push @data, $line;
		$in_section = 1;
		next;
	}
	if ($line =~ /<\/node>/) {
		#push last line and then change segment to json
		$in_section = 0;
		push @data, $line;
		#if json, process xml and convert to json
		if ($file_type eq 'json' || $file_type eq 'both') {
			process_data_json();
		}
		#if csv, process xml and convert to csv
		if ($file_type eq 'csv' || $file_type eq 'both') {
			process_data_csv();
		}

		@data = ();
		next;
	}
	#process vulnerabilities if command specifies. 
	if ($vuln_status eq 'vuln_on')
	{
		if ($line =~ /<vulnerability .*>/) {
			push @data, $line;
			$in_section = 1;
			next;
		}
		if ($line =~ /<\/vulnerability>/) {
			$in_section = 0;
			push @data,$line;
			process_vul();
			next;
		}
	}
	if ($in_section) {
		#push data into line if inside node segment
		push @data, $line;
		next;
	}
}

#depending on user input, close file
if ($file_number eq 'single' || $file_number eq 'both') {
	if ($file_type eq 'csv' || $file_type eq 'both') {
		close $csv_of;
	}
	if ($file_type eq 'json' || $file_type eq 'both') {
		close $json_of;
	}
}

#close vulnerabiliy files
if ($vuln_status eq 'vuln_on'){
	close $vuln_csv;
	close $vuln_json;
}

#This data processes the xml seghments and converts them to json
sub process_data_json {
	#code for converting data to json
	return if not @data;
	my $data = join('',@data);
	my $blank = 'None';

	#convert data to hash
	my $node = $XML2HASH->fromXMLStringtoHash($data);
	$data = 0;

	#get filename from hash
	my $name = $node->{'node'}{'device-id'};
	my $IP = $node->{'node'}{'address'};
	my $hardware_address = $node->{'node'}{'hardware-address'};
	$hardware_address = $blank unless $hardware_address;
	$IP = $blank unless $IP;

	#add variables to hash for conversion to json
	my $unique_key = $IP.'_'.$hardware_address;
	$node->{'node'}{'unique-key'} = $unique_key;
	$node->{'node'}{'export-date'} = $export_date;
	$node->{'node'}{'customrisk'} = '';

	#convert to json
	my $JSON = encode_json($node);
	$node = 0;
	my $fo;

	#write to different files depending on user input
	if ($file_number eq 'mult' || $file_number eq 'both')
	{
		#open separate file for each node
		my $file_out = "files/".$unique_key.'.json';
		open($fo, '>', $file_out) or die "Could not open '$file_out' $!";
		#print unique key and json to file
		print $fo '{"index":{"_id":"'.$unique_key.'"}}'."\n";
		print $fo $JSON."\n";
	}
	if ($file_number eq 'single' || $file_number eq 'both') {
		#print unique key and json to file
		print $json_of '{"index":{"_id":"'.$unique_key.'"}}'."\n";
		print $json_of $JSON."\n";
	}

	#clear memory
	$JSON = 0;

	#close separate file
	if ($file_number eq 'mult' || $file_number eq 'both') {
		close $fo;
	}
}

#This data processes the xml seghments and converts them to csv
sub process_data_csv {
	#set what writes to blank spots in csv
	return if not @data;
	my $data = join('',@data);
	my $blank = 'None';
	my $fo;

	#variable that checks if vulnerability has been printed
	my $count = 0;

	#convert data to hash
	my $node = $XML2HASH->fromXMLStringtoHash($data);

	#pull file info from hash
	my $IP = $node->{'node'}{'address'};
	my $hardware_address = $node->{'node'}{'hardware-address'};
	my $device_id = $node->{'node'}{'device-id'};
	my $risk_score = $node->{'node'}{'risk-score'};
	my $host_name = $node->{'node'}{'names'}{'name'}[1]{'text'} if eval { exists $node->{'node'}{'names'}{'name'}[1]{'text'}};
	my $name = $node->{'node'}{'names'}{'name'}[0]{'text'} if eval { exists $node->{'node'}{'names'}{'name'}[0]{'text'}};
	my $site_name = $node->{'node'}{'site-name'};
	my $tests = $node->{'node'}{'tests'}{'test'};
	my $endpoints = $node->{'node'}{'endpoints'}{'endpoint'};

	#make blank if variable is not found
	$hardware_address = $blank unless $hardware_address;
	$risk_score = $blank unless $risk_score;
	$IP = $blank unless $IP;
	$host_name = $blank unless $host_name;
	$site_name = $blank unless $site_name;
	$name = $blank unless $name;
	$hardware_address = $blank unless $hardware_address;
	$IP = $blank unless $IP;

	#csv file name
	if ($file_number eq 'mult' || $file_number eq 'both') {
		my $file_out = "files/".$IP.'_'.$hardware_address.'.csv';
		open($fo, '>', $file_out) or die "Could not open '$file_out' $!";
		print $fo $node_header;
	}

	#reformat variables and make unique key
	my $sitename = '"'.$site_name.'"';
	my $unique_key = $IP.'_'.$hardware_address.'_';
	#get static values for node
	my $first_part_of_csv = "$device_id,$sitename,$risk_score,$console,$host_name,$name,$IP,$hardware_address";

	#iterate through vulnerabilities in tests
	$count = tests_of_node_to_csv($tests,$first_part_of_csv,$fo,$count,$unique_key);

	#iterate through vulnerabilities in  endpoints
	if (ref($endpoints) eq 'ARRAY') {
		foreach my $end (@{$endpoints}) {
			my $end_tests = $end->{'services'}{'service'}{'tests'}{'test'};
			#interate through tests in given tests array
			$count = tests_of_node_to_csv($end_tests,$first_part_of_csv,$fo,$count,$unique_key);
		}
	} else {
		my $end_tests = $endpoints->{'services'}{'service'}{'tests'}{'test'} if eval {exists $endpoints->{'services'}{'service'}{'tests'}{'test'}};
		$end_tests = $blank unless $end_tests;
		if ($end_tests eq 'None') {

		} else {
			$count = tests_of_node_to_csv($end_tests,$first_part_of_csv,$fo,$count,$unique_key);
		}
	}
}

#write each vulnerability to single csv
sub process_vul {
	return if not @data;

	#join data into one line
	my $data = join('',@data);
	@data = ();
	my $_title;
	my $blank = 'None';

	#Convert vulnerability xml to perl hash
	my $vul_hash = $XML2HASH->fromXMLStringtoHash($data);

	#pull data from hash to add to csv
	my $vul = $vul_hash->{'vulnerability'};
	my $vulnid = $vul->{'id'};
	my $title = $vul->{'title'};
	($_title = $title) =~ /"([^"]*)"/;
	my $new_title = '"'.$_title.'"';
	my $severity = $vul->{'severity'};
	my $pciSeverity = $vul->{'pciSeverity'};
	my $cvssScore = $vul->{'cvssScore'};
	my $cvssVector = $vul->{'cvssVector'};
	my $pub = $vul->{'published'};
	my $added = $vul->{'added'};
	my $mod = $vul->{'modified'};
	my $riskscore = $vul->{'riskScore'};
	my $exploits = $vul->{'exploits'}{'exploit'};
	my ($exploit_count, $lowest_skill) =cycle_through_exploits($exploits);
	$lowest_skill = $blank unless $lowest_skill;

	#add data to hash for json
	$vul->{'export_date'} = $export_date;
	my ($custom, $days_to_fix) = calculate_custom_risk($riskscore);
	my $due_date = get_due_date($days_to_fix);
	$vul->{'due_date'} = $due_date;
	$vul->{'customrisk'} = $custom;
	$vul_hash->{'vulnerability'} = $vul;

	#convert hash to json
	my $JSON = encode_json($vul_hash);

	#print json id and json
	print $vuln_json '{"index":{"_id":"'.$vulnid.'"}}'."\n";
	print $vuln_json $JSON."\n";

	#print to csv
	print $vuln_csv "$vulnid,$new_title,$cvssScore,$cvssVector,$severity,$pciSeverity,$exploit_count,$lowest_skill,$pub,$added,$mod,$riskscore,$custom,$export_date,$days_to_fix,$report_date,$due_date\n";
}

#function to get exploit number
sub cycle_through_exploits {
	my $exploits = $_[0];
	my $count = 0;
	my $lowest = '';
	my $blank = 'None';
	my $skill;
	if (ref($exploits) eq 'ARRAY') {
		foreach my $exploit (@{$exploits}) {
			$skill = $exploit->{'skillLevel'};
			$skill = $blank unless $skill;
			if ($skill eq 'Novice' || $skill eq 'Intermediate' || $skill eq 'Expert') {
				$count++;
			}
			if ($lowest eq '' || $lowest eq 'Expert') {
				$lowest = $skill;
				next;
			}
			if ($lowest eq 'Novice') {
				next;
			}
			if ($lowest eq 'Intermediate') {
				if ($skill eq 'Novice') {
					$lowest = $skill;
					next;
				}
				if ($skill eq 'Intermediate' || $skill eq 'Expert') {
					next
				}
			}
		}
	} else {
		$skill = $exploits->{'skillLevel'};
		$skill = $blank unless $skill;
		if ($skill eq 'Novice' || $skill eq 'Intermediate' || $skill eq 'Expert') {
			$count++;
		}
		if ($lowest eq '' || $lowest eq 'Expert') {
			$lowest = $skill;
		}
		if ($lowest eq 'Novice') {
		}
		if ($lowest eq 'Intermediate') {
			if ($skill eq 'Novice') {
				$lowest = $skill;
				$count++;
			}
			if ($skill eq 'Intermediate' || $skill eq 'Expert') {
			}
		}
	}
	$lowest = $blank unless $lowest;
	return ($count,$lowest);

}



##Function to iterate through tests in endpoints and in regular spot
sub tests_of_node_to_csv {
	#get input of function
	my $blank = 'None';
	my $tests = $_[0];
	my $first_part_of_csv = $_[1];
	my $fo = $_[2];
	my $count = $_[3];
	my $unique_key = $_[4];

	#iterate through tests array
	if (ref($tests) eq 'ARRAY'){
		foreach my $test (@{$tests}) {
			#set values from each test
			my $scan_id = $test->{'scan-id'};
			my $id = $test->{'id'};
			my $u_key = $unique_key.$id;
			my $vul_since = $test->{'vulnerable-since'};
			my $status = $test->{'status'};
			my $pci = $test->{'pci-compliance-status'};

			#set to blank if value is not present
			$scan_id = $blank unless $scan_id;
			$id = $blank unless $id;
			$vul_since = $blank unless $vul_since;
			$status = $blank unless $status;
			$pci= $blank unless $pci;

			#write to csv depending on user input
			if ($file_number eq 'mult' || $file_number eq 'both') {
				#if there is no vulnerability, and $count has been set, do not print
				if ($id eq $blank and $count == 1) {

				} else {
					#print and set count to 1
					print $fo "$first_part_of_csv,$scan_id,$id,$vul_since,$pci,$u_key,\n";
					$count = 1;
				}
			}
			if ($file_number eq 'single' || $file_number eq 'both') {
				if ($id eq $blank and $count == 1) {

				} else {
					print $csv_of "$first_part_of_csv,$scan_id,$id,$vul_since,$pci,$u_key,\n";
					$count = 1;
				}
			}
		}
	} else { 
		#if only one test, do not iterate through, get values
		my $scan_id = $tests->{'scan-id'};
		my $id = $tests->{'id'};
		my $vul_since = $tests->{'vulnerable-since'};
		my $status = $tests->{'status'};
		my $pci = $tests->{'pci-compliance-status'};

		#set to blank if value is not in test
		$scan_id = $blank unless $scan_id;
		$id = $blank unless $id;
		my $u_key = $unique_key.$id;
		$vul_since = $blank unless $vul_since;
		$status = $blank unless $status;
		$pci= $blank unless $pci;

		#write to csv
		if ($file_number eq 'mult' || $file_number eq 'both') {
			if ($id eq $blank and $count == 1) {

			} else {
				print $fo "$first_part_of_csv,$scan_id,$id,$vul_since,$pci,$u_key,\n";
				$count = 1;
			}
		}
		if ($file_number eq 'single' || $file_number eq 'both') {
			if ($id eq $blank and $count == 1) {

			} else {
				print $csv_of "$first_part_of_csv,$scan_id,$id,$vul_since,$pci,$u_key,\n";
				$count = 1;
			}
		}
	}
	#return count for future use
	return $count;
}

## GET time and return timestamp
sub get_date {
	#get local time
	(my $_sec,my $_min,my $_hour,my $mday,my $mon,my $_year,my $wday,my $yday,my $isdst) = localtime();
	$_year += 1900;

	#make numbers 2 digits long
	if ($mon < 10) {
		$mon = $mon;
	}
	if ($_hour < 10) {
		$_hour = '0'.$_hour;
	}
	if ($_min < 10) {
		$_min = '0'.$_min;
	}
	if ($mday < 10) {
		$mday = $mday;
	}
	if ($_sec < 10) {
		$_sec = '0'.$_sec;
	}
	return ($mon+1,$mday,$_year);
}

sub calculate_custom_risk {
	# calculate custom risk from given levels and nexpose risk score
	my $risk = int($_[0]);
	if ($risk >= 0 and $risk < 300) {
		return ('Low',365);
	} 
	elsif ($risk >= 300 and $risk < 500) {
		return ('Medium',180);
	}
	elsif ($risk >= 500 and $risk < 700) {
		return ('High',90);
	}
	elsif ($risk >= 700 and $risk < 900) {
		return ('Critical',30);
	}
	elsif ($risk >= 900 and $risk <= 1000) {
		return ('Urgent',2);
	} else {
		return 'None';
	}
}

sub get_due_date {
	# get due date from the given report date and the number of days until it is due
	my $days = int($_[0]);
	my $d_year;
	my $d_month;
	my $d_day;
	# if year, add 1 to year
	if ($days == 365) {
		$d_year = $r_year+1;
		$d_day = $r_day;
		$d_month = $r_month;
	}
	# if 2 days, add
	elsif ($days == 2) {
		$d_day = $r_day+2;
		$d_month = $r_month;
		$d_year = $r_year;
	} else {
	# if certain number of months, use % operator
		print "$days";
		$d_month = $r_month + $days/30;
		print " $d_month\n";
		if ($d_month > 12) {
			$d_year = $r_year+1;
		} else {
			$d_year = $r_year;
		}
		$d_month = $d_month % 12;
		$d_day = $r_day
	}
	return $d_month.'/'.$d_day.'/'.$d_year;
}
	
	   	

