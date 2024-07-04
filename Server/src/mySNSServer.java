import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.Scanner;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * server program
 */
public class mySNSServer {

	public static void main(String[] args) {

		// Solicita a senha para o usuário admin
		System.out.print("Enter admin password : ");
		Scanner scanner = new Scanner(System.in);
		String password = scanner.nextLine();
		System.out.println("====================================\nAuthentication admin:");

		AuxUser.createUsersFile(password);

		// AuxUser.loadUsersFromFile();

		if (AuxUser.authentication("admin", password)) {
			System.out.println("====================================\nMac verification:");
			File f = new File("users.mac");
			if (!f.isFile()) {
				System.out.println("	\u001B[33m»» File users.mac does not exist\u001B[0m");
				System.out.print("	\u001B[33m   Want to create it? (y/n): \u001B[0m");
				String answer = scanner.nextLine();
				if (answer.equals("y")) {
					AuxCipher.generateMAC(AuxUser.genSecretKeyMac(password));
				} else {
					System.out.println("	\u001B[31m»» MAC file does not exist (Server shutdown)\u001B[0m");
					System.exit(0);
				}
			} else {
				Boolean verify = AuxCipher.verifyMAC(AuxUser.genSecretKeyMac(password));
				if (!verify) {
					System.out.println("	\u001B[31m»» MAC verification failed (Server shutdown)\u001B[0m");
					System.exit(0);
				} else {
					System.out.println("	\u001B[32m»» MAC verification success\u001B[0m");
				}
			}

			scanner.close();

			System.out.println("====================================\nServer initialization:");
			System.out.println("	»» servidor: main");
			mySNSServer server = new mySNSServer();
			server.startServer(args[0], password);
		} else {
			System.out.print("	\u001B[31m»» Wrong password\u001B[0m");
			scanner.close();
		}
	}

	public void startServer(String port, String password) {
		ServerSocket sSoc = null;

		try {
			ServerSocketFactory ssf = SSLServerSocketFactory.getDefault();
			sSoc = ssf.createServerSocket(Integer.parseInt(port), 0, InetAddress.getByName("0.0.0.0"));
			// sSoc = new ServerSocket(Integer.valueOf(port), 0,
			// InetAddress.getByName("0.0.0.0"));

		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(-1);
		}

		while (true) {
			try {
				Socket inSoc = sSoc.accept();
				ServerThread newServerThread = new ServerThread(inSoc, password);
				newServerThread.start();
			} catch (IOException e) {
				e.printStackTrace();
			}

		}
		// sSoc.close();
	}

	class ServerThread extends Thread {

		private Socket socket = null;
		private String passwordAdmin = null;

		ServerThread(Socket inSoc, String password) {
			socket = inSoc;
			this.passwordAdmin = password;

		}

		public void run() {
			ObjectOutputStream outStream;
			ObjectInputStream inStream;

			try {
				outStream = new ObjectOutputStream(socket.getOutputStream());
				inStream = new ObjectInputStream(socket.getInputStream());
				/*
				 * Order of sends from client
				 * 
				 * option -> n. of calls -> -u name -> String[] files -> (Cycle for) -> len of
				 * the file
				 */

				String option = (String) inStream.readObject();
				String medico = (String) inStream.readObject();
				String username = (String) inStream.readObject();
				String password = (String) inStream.readObject();

				System.out.println("====================================\nMac verification:");
				char verifyMac = 'o';
				Boolean verify = AuxCipher.verifyMAC(AuxUser.genSecretKeyMac(this.passwordAdmin));
				if (!verify) {
					System.out.println("	\u001B[31m»» MAC verification failed (Server shutdown)\u001B[0m");
					verifyMac = 'f';
				} else {
					System.out.println("	\u001B[32m»» MAC verification success\u001B[0m");
				}
				outStream.writeObject(verifyMac);
				if (verifyMac == 'f') {
					System.exit(0);
				}

				if ((!option.equals("-g") && !option.equals("-au") && AuxUser.authentication(medico, password))
						|| option.equals("-au") || option.equals("-g") && AuxUser.authentication(username, password)) {
					if (!option.equals("-au")) {
						outStream.writeObject("true");
						System.out.println("====================================\nUser Validation:");
						System.out.println("	\u001B[32m»» Successfully\u001B[0m");

					} else {
						System.out.println("====================================\nOption " + option + ":");
						if (AuxUser.getUserFromFile(username) != null) {
							System.out.println("====================================\nCreate User:");
							System.out.println("	\u001B[31m»» username: " + username + " already exist!\u001B[0m");
							outStream.writeObject("false");
						} else {
							byte[] salt = AuxCipher.generateSalt();
							String saltString = AuxCipher.bytesToHex(salt);
							System.out
									.println("	\u001B[32m»» username: " + username + " add successfully!\u001B[0m");
							outStream.writeObject("true");
							AuxUser.addUser(username, AuxCipher.hashPassword(password, salt), saltString);
							AuxCipher.generateMAC(AuxUser.genSecretKeyMac(this.passwordAdmin));
						}
					}

					int nCalls = (Integer) inStream.readObject();
					outerloop: for (int i = 0; i < nCalls; i++) {

						username = ((String) inStream.readObject()).toLowerCase();

						// Construct directory path ex: files/maria

						String directoryPath = "files/" + username;
						if (option.equals("-au")) {
							directoryPath = "files/certs";
						}

						// create directory
						Boolean dir = new File(directoryPath).mkdirs();

						if (option.equals("-g")) {
							System.out.println("====================================\nOption " + option + ":");
							String filename = (String) inStream.readObject();

							List<Path> matchingFiles = Files.walk(Path.of(directoryPath))
									.filter(path -> path.getFileName().toString().startsWith(filename))
									.collect(Collectors.toList());

							outStream.writeObject(matchingFiles.size());

							if (!matchingFiles.isEmpty()) {
								// Envia cada arquivo correspondente para o cliente
								for (Path filePath : matchingFiles) {

									File fi = new File(filePath.toString());

									if (fi.getName().contains(".assinatura.")) {
										String[] el = fi.getName().split("\\.");
										medico = el[el.length - 1];
									}

									outStream.writeObject(fi.getName());

									// verificacao de existencia de files no servidor
									if ((Boolean) inStream.readObject() == true) {
										continue;
									}
									outStream.writeObject(fi.length());

									FileInputStream fis = new FileInputStream(filePath.toString());
									byte[] bi = new byte[256];
									int k = fis.read(bi);
									while (k != -1) {
										outStream.write(bi, 0, k);
										k = fis.read(bi);
									}
									outStream.flush();
									fis.close();
								}

								Boolean certVer = (Boolean) inStream.readObject();
								if (certVer) {
									char flag = (char) inStream.readObject();
									if (flag == 'c') {
										AuxUser.verifyCert(medico, outStream);
									}
								}
								System.out
										.println(" 	\u001B[32m»» associated files sent to client " + "\u001B[0m");
							} else {
								System.out
										.println(" 	\u001B[31m»» there are no files associated to the file: " + filename + "\u001B[0m");
							}

						} else {
							if (!option.equals("-au")) {
								System.out.println("====================================\nOption " + option + ":");
							}
							String[] filesPath = (String[]) inStream.readObject();

							boolean atLeastOneExists = false;
							// AuxUser.authentication(username, directoryPath);
							for (String fil : filesPath) {
								File file = new File(directoryPath, fil);
								if (file.exists()) {
									atLeastOneExists = true;
									outStream.writeObject(atLeastOneExists);
									continue outerloop;
								}
							}
							outStream.writeObject(atLeastOneExists);

							if (option.equals("-sc") || (option.equals("-se") && (i % 2 == 0 || i == 0))) {
								char flag = (char) inStream.readObject();
								if (flag == 'c') {
									AuxUser.verifyCert(username, outStream);
								}

							}

							for (String filePath : filesPath) {
								File f = new File(filePath);
								// check if file exist
								File fi = new File(directoryPath + "/" + f.getName());

								if (!fi.isFile()) {

									long fileSize = (long) inStream.readObject();
									FileOutputStream fos = new FileOutputStream(directoryPath + "/" + f.getName());
									BufferedOutputStream bos = new BufferedOutputStream(fos);

									byte[] buffer = new byte[1024];
									int bytesRead;

									while (fileSize > 0
											&& (bytesRead = inStream.read(buffer, 0,
													(int) Math.min(buffer.length, fileSize))) != -1) {
										bos.write(buffer, 0, bytesRead);
										fileSize -= bytesRead;
									}

									bos.flush();
									bos.close();
									Arrays.fill(buffer, (byte) 0);
									System.out.print("	\u001B[32m»» File: " + f.getName() + " saved!\u001B[0m\n");

								} else {
									System.out.print(
											"	\u001B[33m»» File: " + f.getName()
													+ " already exists in server!\u001B[0m\n");
									continue;
								}
							}

						}
					}
				} else {
					outStream.writeObject("false");

					System.out.println("	\u001B[31m»» Wrong password" + "\u001B[0m");

				}

				outStream.close();
				inStream.close();
				socket.close();

			} catch (SocketException e) {
				/*System.out.println("====================================\nServer Status");
				System.out
						.println("	\u001B[31m»» Client connection reset or terminated unexpectedly: " + e.getMessage()
								+ "\u001B[0m");*/
			} catch (IOException e) {
				/*System.out.println("====================================\nServer Status");
				System.out.println("	\u001B[31m»» Error reading from socket: " + e.getMessage() + "\u001B[0m");*/
			} catch (ClassNotFoundException e) {
				/*System.out.println("====================================\nServer Status");
				System.out.println(" \u001B[31m»» Error deserializing object: " + e.getMessage() + "\u001B[0m");*/
			} finally {
				try {
					if (socket != null && !socket.isClosed()) {
						socket.close();
					}
				} catch (IOException e) {
					/*System.out.println("====================================\nServer Status");
					System.out.println(" \u001B[31m»» Error closing socket: " + e.getMessage() + "\u001B[0m");*/
				}
			}

		}
	}
}