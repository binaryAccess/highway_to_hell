import argparse
##################################################################
#                                                                #
# A script which converts multiline Invoke-kerberoast tickets    #
# into a single line, ready to crack with Hashcat hashes         #
#                                                                #
# Author: Slavi Parpulev                                         #
# version 1.0                                                    #
#                                                                #
##################################################################

def read_kerberoast_file(filename):
	with open(filename, 'r') as f:
		content = f.readlines()
	return content


def processFile(raw_kerberoast):
	hashDetected = False
	all_hashes = []
	current_hash = []

	for aLine in raw_kerberoast:
		if "Hash" in aLine:
			hashDetected = True
			current_hash.append(aLine.split(':')[1].strip())

		elif "SamAccountName" in aLine:
			all_hashes.append(''.join(current_hash))
			current_hash = []
			hashDetected = False

		elif hashDetected:
			current_hash.append(aLine.strip())

		else:
			continue

	return all_hashes


def save_file(filename, kerb_tickets):
	with open(filename, 'w') as f:
		f.writelines('\n'.join(kerb_tickets))

	print "Output saved in {0}. Execution completed!".format(filename)



def main():
	banner = r'''

        __      _
        \.'---.//|
         |\./|  \/
        _|.|.|_  \
       /(  ) ' '  \
      |  \/   . |  \
       \_/\__/| |
        V  /V / |
          /__/ /
          \___/\


	'''
	msg = '''
	Converts Invoke-kerberoast -Output Hasscat multiline into single lines ready to crack with Hashcat
	'''

	ap = argparse.ArgumentParser(description=msg)

	ap.add_argument("-f", "--Input_file", required=True, help="Input file - the raw output of Invoke-Kerberoast -Output Hashcat")
	ap.add_argument("-o", "--Output_file", required=True, help="Output file name")

	args = vars(ap.parse_args())

	print banner

	raw_kerberoast_file = read_kerberoast_file(args["Input_file"])

	kerb_tickets = processFile(raw_kerberoast_file)

	save_file(args["Output_file"], kerb_tickets)

if __name__ == '__main__':
	main()
