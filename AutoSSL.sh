HOST=$1
PORT='443'
DATE=$(date +'%Y_%m_%d')

if [ $# -eq 2 ]
then 
	PORT=$2
fi
	
NMAP_OUTFILE=${DATE}_NMAP_SSL_SCAN_${HOST}:${PORT}.txt
SSLSCAN_OUTFILE=${DATE}_SSLSCAN_${HOST}:${PORT}.txt
SSLYZE_OUTFILE=${DATE}_SSLYZE_${HOST}:${PORT}.txt		
OPENSSL_OUTFILE=${DATE}_OPENSSL_${HOST}:${PORT}.txt	

function listScan()
{
	FILENAME=$1

	while IFS= read -r line; do
		HOST=$(cut -d' ' -f1 <<<${line})
		PORT=$(cut -d' ' -f2 <<<${line})
		main $HOST $PORT
	done < $FILENAME

}

function main()
{	
	echo 'Starting NMAP Scan!'
	echo "nmap --script ssl-enum-ciphers -p ${PORT} ${HOST}" > $NMAP_OUTFILE
	nmap --script ssl-enum-ciphers -p $PORT $HOST >> $NMAP_OUTFILE

	grep 'TLSv1.0\|TLSv1.1' $NMAP_OUTFILE &>/dev/null
	if [ $? -eq 0 ]
	then
		echo 'Weak TLS versions found in $NMAP_OUTFILE!'
	fi

	echo 'Starting SSLScan!'
	echo "sslscan ${HOST}:${PORT}" > $SSLSCAN_OUTFILE 
	sslscan $HOST:$PORT >> $SSLSCAN_OUTFILE

	echo 'Starting SSLyze!'
	echo "sslyze ${HOST}:${PORT}" > $SSLYZE_OUTFILE
	sslyze $HOST:$PORT >> $SSLYZE_OUTFILE 

	echo 'Starting OpenSSL!'
	(echo 'R') | openssl s_client -connect $HOST:$PORT &> $OPENSSL_OUTFILE 

	cipher_check
}

function cipher_check()
{
	CIPHERS=$(grep -E '((TLS|SSL)[A-Z0-9\_]+)' *NMAP* | awk '{print $2}' | sort -u)

	if [ -f "cipher_results" ]; then
		rm cipher_results
	fi

	printf '%s\n' "$CIPHERS" |
	while IFS= read -r TLS_LINE
	do
		#echo $TLS_LINE
		TXT=$(curl -L -s https://ciphersuite.info/cs/$TLS_LINE)
		if grep -q -i 'weak' <<< $TXT; then
			echo "${TLS_LINE}\tWEAK" >> cipher_results
		elif grep -q -i 'insecure' <<< $TXT; then
			echo "${TLS_LINE}\tINSECURE" >> cipher_results
		elif grep -q -i 'secure' <<< $TXT; then
			echo "${TLS_LINE}\tSECURE" >> cipher_results
		else 
			echo "${TLS_LINE}\tUNKNOWN" >> cipher_results
		fi	
	done 

	sort -t$'\t' -k2 cipher_results | column -t | tee cipher_results 
}

function usage()
{
	echo ' USAGE EXAMPLES:'
	echo './AutoSSL.sh <host> <port if not 443>'
	echo './AutoSSL.sh -f <path to list of hosts>'
}

function clean()
{
	rm *_NMAP_SSL_SCAN_*.txt *_SSLYZE_*.txt *_SSLSCAN_*.txt *_OPENSSL_*.txt
}

function check_for_ssl_programs()
{
	INSTALLED=0

	if ! command -v sslyze &> /dev/null
	then
		echo 'sslyze not found!'
		INSTALLED=1
	fi

	if ! command -v nmap &> /dev/null
	then
		echo 'nmap not found!'
		INSTALLED=1
	fi

	if ! command -v sslscan &> /dev/null
	then
		echo 'sslscan not found!'
		INSTALLED=1
	fi

	if ! command -v openssl &> /dev/null
	then
		echo 'openssl not found!'
		INSTALLED=1
	fi

	return $INSTALLED
}

if [ $# -le 0 ] || [ $1 == '-h' ]
then
	usage
	exit
elif ! check_for_ssl_programs
then
	echo 'Install the missing component(s)!'
	exit
elif [ $1 == 'clean' ] 
then
	clean
elif [ $1 == '-f' ]
then
	if [ ! -f $2 ]ß
	then 
		echo 'File not found!'
	else
		listScan $2
	fi
else
	main $@
fi

