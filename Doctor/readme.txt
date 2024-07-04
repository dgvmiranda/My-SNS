Compile java program
javac src/*.java

No errors
	Create user
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client' -cp src mySNS -a ip:3000 -au drwho dr.who drwho.crt

	User: goncalo
	Cipher
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client'  -cp src  mySNS -a ip:3000 -u goncalo -p dr.who -m drwho -sc Patient_Medical_History_Report_Goncalo.pdf

	Sign
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client'  -cp src  mySNS -a ip:3000 -u goncalo -p dr.who -m drwho -sa Patient_Medical_History_Report_Goncalo.pdf

	Envelope
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client'  -cp src  mySNS -a ip:3000 -u goncalo -p dr.who -m drwho -se Patient_Medical_History_Report_Goncalo.pdf

	User: maria

	Cipher
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client'  -cp src  mySNS -a ip:3000 -u goncalo -p dr.who -m drwho -sc Student_Medical_Incident_Report_Maria.pdf

	Sign
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client'  -cp src  mySNS -a ip:3000 -u goncalo -p dr.who -m drwho -sa Student_Medical_Incident_Report_Maria.pdf

	Envelope
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client'  -cp src  mySNS -a ip:3000 -u goncalo -p dr.who -m drwho -se Student_Medical_Incident_Report_Maria.pdf