import java.io.*;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocketFactory;

/**
 * Deals with the connection aspects of the client
 */
public class cConnection {
	private final String ADDRESS;
	private final String PORT;
	private Socket sClient;
	private SocketFactory sFactory;
	private ObjectInputStream objInStream;
	private ObjectOutputStream objOutStream;

	/**
	 * Constructor
	 */
	public cConnection(String address, String port) {
		ADDRESS = address;
		PORT = port;
	}

	/*
	 * Create a connection
	 */
	public boolean connect() {
		try {
			sFactory = SSLSocketFactory.getDefault();
			this.sClient = sFactory.createSocket(InetAddress.getByName(ADDRESS), Integer.valueOf(PORT));
			objInStream = new ObjectInputStream(sClient.getInputStream());
			objOutStream = new ObjectOutputStream(sClient.getOutputStream());
			return true;
		} catch (NumberFormatException e) {
			return false;
		} catch (UnknownHostException e) {
			System.out.println("====================================\nConnection Status:");
			System.out.println("	\u001B[31m»» Unknown host!\u001B[0m");
			return false;
		} catch (ConnectException e) {
			System.out.println("====================================\nConnection Status:");
			System.out.println("	\u001B[31m»» Cannot connect to server\u001B[0m");
			return false;
		} catch (SSLHandshakeException e) {
			System.out.println("====================================\nConnection Status:");
			System.out.println(
					"	\u001B[31m»» SSL failed unable to find valid certification path to requested target \u001B[0m");
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
	}

	/*
	 * Close ObjectOutputStream
	 */
	public void closeOutput() {
		try {
			objOutStream.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	/*
	 * Close ObjectInputStream
	 */
	public void closeInput() {
		try {
			objInStream.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	/*
	 * Close the connection
	 */
	public void close() {
		try {

			sClient.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/*
	 * sending an object
	 */
	public void sendContent(Object o) {
		try {
			objOutStream.writeObject(o);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/*
	 * sending a file
	 */
	public void sendFile(String path) {
		try {
			FileInputStream fis = new FileInputStream(path);
			byte[] b = new byte[256];
			int i = fis.read(b);
			while (i != -1) {
				objOutStream.write(b, 0, i);
				i = fis.read(b);
			}
			fis.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/*
	 * sending an object
	 */
	public Object recieveContent() {
		try {
			Object o = objInStream.readObject();
			return o;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	/*
	 * Witter function
	 */
	public void write(byte[] b, int off, int len) {
		try {
			objOutStream.write(b, off, len);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/*
	 * Reader function
	 */
	public int read(byte[] b, int off, int len) {
		try {
			return objInStream.read(b, off, len);
		} catch (IOException e) {
			e.printStackTrace();
			return 0;
		}
	}

	/*
	 * sending byte array
	 */
	public void sendBytes(byte[] b) {
		try {
			objOutStream.write(b);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/*
	 * Getter for getObjInStream
	 */
	public ObjectInputStream getObjInStream() {
		return objInStream;
	}

	/*
	 * Getter for getObjOutStream
	 */

	public ObjectOutputStream getObjOutStream() {
		return objOutStream;
	}

}