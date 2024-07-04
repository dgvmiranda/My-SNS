Compile java 
javac src/*.java

No errors 
	Create user
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client' -cp src mySNS -a ip:3000 -au maria maria maria.crt

	Get maira file Student_Medical_Incident_Report_Maria.pdf
	java '-Djavax.net.ssl.trustStore=truststore.client' '-Djavax.net.ssl.trustStorePassword=client' -cp src mySNS -a localhost:3000 -u maria -p 123456 -g Student_Medical_Incident_Report_Maria.pdf