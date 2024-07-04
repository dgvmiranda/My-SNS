Compile java 
javac src/*.java

No errors 
	Create user
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client' -cp src mySNS -a ip:3000 -au goncalo goncalo goncalo.crt

	Get goncalo file Patient_Medical_History_Report_Goncalo.pdf
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client'  -cp src  mySNS -a ip:3000 -u goncalo -p goncalo -g Patient_Medical_History_Report_Goncalo.pdf