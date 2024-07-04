Iniciar o server:
javac src/*.java
java '-Djavax.net.ssl.keyStore=keystore.server' '-Djavax.net.ssl.keyStorePassword=server' -cp src mySNSServer 3000