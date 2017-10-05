all: 
	chmod +x cbc-enc
	chmod +x cbc-dec
	chmod +x ctr-enc
	chmod +x ctr-dec
	pip install pycrypto

clean:
	.pyc
