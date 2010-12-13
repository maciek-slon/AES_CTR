#!/usr/bin/python

import subprocess

f = open('machine.openmpi', 'w');

for i in range(1, 13):
	host = "ux"+str(i);
	code = subprocess.call(['ping',host,'-c1']);
	if code == 0:
		line = host+".ia.pw.edu.pl slots=2 max_slots=2\n"
		print line
		f.write(line);


f.close();
