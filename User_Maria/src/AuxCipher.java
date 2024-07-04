import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;

public class AuxCipher {
	private SecretKey key;
	private Cipher c;
	private File originalFile;
	private String username, medico;
	private cConnection sc;
	// private PublicKey publicKey;
	private String password;

	/**
	 * Constructor to signature and envelop
	 * 
	 * @param String      type the type used for the generation of the cipher
	 * @param String      path the path of the file
	 * @param String      username the username of the authenticated user
	 * @param String      medico the name of the doctor
	 * @param cConnection sc instance of connection to server
	 */
	public AuxCipher(String type, String path, String username, String medico, String password, cConnection sc) {
		KeyGenerator kg;
		try {
			kg = KeyGenerator.getInstance(type);
			kg.init(128);
			this.key = kg.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		try {
			c = Cipher.getInstance(type);
			c.init(Cipher.ENCRYPT_MODE, key);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		this.originalFile = new File(path);
		this.username = username;
		this.medico = medico;
		this.sc = sc;
		this.password = password;
	}

	public void encode(String termina) {
		try {

			FileInputStream fis = new FileInputStream(originalFile.getName());
			FileOutputStream fos = new FileOutputStream(originalFile.getName() + termina);

			CipherOutputStream cos = new CipherOutputStream(fos, c);
			byte[] b = new byte[256];
			int i = fis.read(b);
			while (i != -1) {
				cos.write(b, 0, i);
				i = fis.read(b);
			}
			cos.close();
			fis.close();

			File file = new File(originalFile.getName() + termina);
			sc.sendContent(file.length());
			sc.sendFile(originalFile.getName() + termina);
			file.delete();

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public Boolean decypher(String fileChave, String fileCifrado) {
		try {
			FileInputStream kis = new FileInputStream(fileChave);
			byte[] keyEncoded = new byte[256];
			kis.read(keyEncoded);
			kis.close();

			KeyStore kstore = createKeyStore(this.username);
			Key pKey = kstore.getKey(this.username, this.password.toCharArray()); // alias do utilizador

			Cipher c = Cipher.getInstance("RSA");
			c.init(Cipher.UNWRAP_MODE, pKey);
			Key key = c.unwrap(keyEncoded, "AES", Cipher.SECRET_KEY);

			Cipher c1 = Cipher.getInstance("AES");
			c1.init(Cipher.DECRYPT_MODE, key);

			FileInputStream fis = new FileInputStream(fileCifrado);
			FileOutputStream fos = new FileOutputStream(originalFile.getName() + ".decifrado");
			CipherInputStream cis = new CipherInputStream(fis, c1);

			byte[] buffer = new byte[256];
			int i = cis.read(buffer);

			while (i != -1) {
				fos.write(buffer, 0, i);
				i = cis.read(buffer);
			}

			fos.close();
			fis.close();
			cis.close();

			// Zona de extreminacao :) se naoo for para guardar assinaturas, mata-las aqui
			// :)
			File fC = new File(fileCifrado);
			fC.delete();

			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;

		}
	}

	public boolean hybrid(String termina) {

		// verificacao de existencia de files no servidor
		boolean verify = (boolean) sc.recieveContent();
		if (verify) {
			System.out.print("	\u001B[33m»» File: " + originalFile.getName()
					+ " was already cifrado and saved by a doctor!\n\u001B[0m");
			System.out.print("	\u001B[33m»» This operation would create duplicated files in the server!\n\u001B[0m");
			return true;
		}

		char flag = AuxCipher.verifyCertificate(username, medico, password);
		sc.sendContent(flag);

		if (flag == 'c') {
			Boolean res = importCert(medico, username, password);
			if (!res) {
				return true;
			}
		}

		this.encode(termina);
		this.generateKeyFile();
		System.out.print("	\u001B[32m»» File: " + originalFile.getName() + " was cifrado and saved! \n\u001B[0m");
		return false;
	}

	public void generateKeyFile() {
		String name = originalFile.getName();
		String filename = name + ".chave_secreta." + username;

		FileOutputStream kos;
		try {
			KeyStore kstore = createKeyStore(this.medico);
			PublicKey publicKey = kstore.getCertificate(this.username).getPublicKey();
			Cipher cPub = Cipher.getInstance("RSA");
			cPub.init(Cipher.WRAP_MODE, publicKey);
			byte[] pubKey = cPub.wrap(this.key);
			kos = new FileOutputStream(filename);
			kos.write(pubKey);
			kos.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

		File file = new File(filename);
		sc.sendContent(file.length());
		sc.sendFile(filename);
		file.delete();
	}

	public boolean Signature() throws Exception {

		// verificacao de existencia de files no servidor
		boolean verify = (boolean) sc.recieveContent();
		if (verify) {
			System.out.print(
					"	\u001B[33m»» File: " + originalFile.getName()
							+ " was already signed and saved by a doctor.\n\u001B[0m");
			System.out.print("	\u001B[33m»» This operation would create duplicated files in the server.\n\u001B[0m");
			return true;
		}

		// envio size file original
		long sizefile = originalFile.length();
		sc.sendContent(sizefile);

		// Chaves
		KeyStore kstore = createKeyStore(this.medico);
		Key privateKey = kstore.getKey(this.medico, this.password.toCharArray());

		// Assinatura e Ler o file
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign((PrivateKey) privateKey);

		FileInputStream fis = new FileInputStream(originalFile.getName());
		byte[] b = new byte[256];
		int i = fis.read(b); // este ciclo assegura que podem ser usados ficheiros de qualquer dimensão
		while (i != -1) { // porque não limitado à dimensão de byte[] do java
			signature.update(b, 0, i);
			sc.write(b, 0, i);
			i = fis.read(b);
		}

		fis.close();
		byte[] digitalSignature = signature.sign(); // assina

		// enviar tamanho e conteudo da assinatura
		long sizeAs = (long) digitalSignature.length;
		sc.sendContent(sizeAs);
		sc.sendBytes(digitalSignature);

		System.out.print("	\u001B[32m»» File: " + originalFile.getName() + " was signed and saved! \n\u001B[0m");
		return false;
	}

	public boolean envelope() {
		try {
			boolean existc = true;
			boolean exista = true;
			// cifra
			String filenamecifra = this.originalFile.getName() + ".seguro";
			String chaveFile = this.originalFile.getName() + ".chave_secreta." + username;
			String[] values = { filenamecifra, chaveFile };
			sc.sendContent(this.username);
			// sc.sendContent(this.password);

			sc.sendContent(values);

			existc = hybrid(".cifrado");

			// assina
			String filenamecopy = this.originalFile.getName() + ".assinado";
			String signatureFile = this.originalFile.getName() + ".assinatura." + medico;
			String[] values1 = { filenamecopy, signatureFile };
			sc.sendContent(this.username);
			sc.sendContent(values1);

			exista = Signature();

			if ((existc == false) && (exista == false)) {
				return false;
			} else {
				return true;
			}

		} catch (Exception e) {
			e.printStackTrace();
			return true;
		}
	}

	public boolean verificG() throws IOException {

		String fileAssinado = null;
		String fileAssinatura = null;
		String fileChave = null;
		String fileCifrado = null;

		sc.sendContent(originalFile.getName()); // nome file origem

		int nCalls = (int) sc.recieveContent(); // n de documentos que existem derivados da origem no server

		if (nCalls == 0) {
			System.out
					.print("	\u001B[33m»» File: " + originalFile.getName()
							+ " doesn't have any associated files in the server! \n\u001B[0m");
			return true;
		}

		for (int i = 0; i < nCalls; i++) {

			String filePath = (String) sc.recieveContent();
			File f = new File(filePath);

			if (!f.isFile()) {
				sc.sendContent(false);
				// get the file size
				long fileSize = (long) sc.recieveContent();

				FileOutputStream fos = new FileOutputStream(f.getName());
				BufferedOutputStream bos = new BufferedOutputStream(fos);

				byte[] buffer = new byte[1024];
				int bytesRead;

				while (fileSize > 0
						&& (bytesRead = sc.read(buffer, 0, (int) Math.min(buffer.length, fileSize))) != -1) {

					bos.write(buffer, 0, bytesRead);
					fileSize -= bytesRead;
				}

				bos.flush();
				bos.close();
				Arrays.fill(buffer, (byte) 0);

				if (f.getName().contains(".assinatura.")) {
					System.out.print("	\u001B[32m»» File: " + f.getName() + " saved! \n\u001B[0m");
					fileAssinatura = f.getName();
				}
				if (f.getName().contains(".assinado")) {
					System.out.print("	\u001B[32m»» File: " + f.getName() + " saved! \n\u001B[0m");
					fileAssinado = f.getName();
				}
				if (f.getName().contains(".chave_secreta.")) {
					System.out.print("	\u001B[32m»» File: " + f.getName() + " saved! \n\u001B[0m");
					fileChave = f.getName();
				}
				if (f.getName().contains(".cifrado") || f.getName().contains(".seguro")) {
					fileCifrado = f.getName();
				}
			} else {
				sc.sendContent(true);
				System.out.print("	\u001B[33m»» File: " + f.getName() + " already exists! \n\u001B[0m");
			}

		}

		// valida as assinaturas se houver
		if (fileAssinatura != null && fileAssinado != null) {
			sc.sendContent(true);
			try {
				String[] el = fileAssinatura.split("\\.");

				char flag = AuxCipher.verifyCertificate(el[el.length - 1], username, password);
				sc.sendContent(flag);

				if (flag == 'c') {
					Boolean res = importCert(username, el[el.length - 1], password);
					if (!res) {
						System.out.print("	\u001B[31m»» The signature of the file could not be validated\u001B[0m");
					} else {
						if (ValidaAss(fileAssinatura, fileAssinado, el[el.length - 1])) {
							System.out.print(
									"	\u001B[32m»» The signature of the file: " + originalFile.getName()
											+ " is valid! \n\u001B[0m");
						} else {
							System.out.print(
									"	\u001B[31m»» The signature of the file: " + originalFile.getName()
											+ " is not valid! \n\u001B[0m");
						}
					}

				}

				else {
					if (ValidaAss(fileAssinatura, fileAssinado, el[el.length - 1])) {
						System.out.print("	\u001B[32m»» The signature of the file: " + originalFile.getName()
								+ " is valid! \n\u001B[0m");
					} else {
						System.out.print(
								"	\u001B[31m»» The signature of the file: " + originalFile.getName()
										+ " is not  valid! \n\u001B[0m");
					}

				}

			} catch (Exception e) {
				e.printStackTrace();
				return true;
			}
		}

		// valida files cifrados se houver
		if (fileChave != null && fileCifrado != null) {
			sc.sendContent(false);
			try {
				if (decypher(fileChave, fileCifrado)) {
					System.out.print(
							"	\u001B[32m»» The file: " + originalFile.getName()
									+ " was received and decripted! \n\u001B[0m");
				} else {
					System.out.print(
							"	\u001B[33m»» The file: " + originalFile.getName()
									+ " was received but not decripted! \n\u001B[0m");
				}
			} catch (Exception e) {
				e.printStackTrace();
				return true;
			}

		}
		return false;
	}

	public Boolean ValidaAss(String fileAss, String fileAssinado, String medico)
			throws KeyStoreException, NoSuchAlgorithmException,
			CertificateException, IOException, InvalidKeyException, SignatureException {

		char flag = verifyCertificate(medico, username, password);
		if (flag == 'c') {
			return false;
		}

		KeyStore kstore = createKeyStore(this.username);
		Certificate cert = (Certificate) kstore.getCertificate(medico);
		Signature s = Signature.getInstance("SHA256withRSA");
		s.initVerify(cert); // s.initVerify(cert);

		FileInputStream fis = new FileInputStream(fileAssinado);
		byte[] b = new byte[2048];
		int i = fis.read(b); // este ciclo assegura que podem ser usados ficheiros de qualquer dimensão
		while (i != -1) { // porque não limitado à dimensão de byte[] do java
			s.update(b, 0, i);
			i = fis.read(b);
		}
		fis.close();

		// ler a assinature do ficherio da assinatura
		FileInputStream fisa = new FileInputStream(fileAss);
		byte[] assinatura = new byte[256];
		fisa.read(assinatura);
		fisa.close();

		boolean res = s.verify(assinatura);

		return res;
	}

	public KeyStore createKeyStore(String user) {
		try {
			FileInputStream kfile = new FileInputStream(user + ".keystore");
			KeyStore kstore = KeyStore.getInstance("PKCS12");
			kstore.load(kfile, this.password.toCharArray());
			return kstore;
		} catch (Exception e) {
			System.out.println("====================================\nKeystore Status:");
			System.out.println("	\u001B[31m»» Erro ao iniciar KeyStore\u001B[0m");
			return null;
		}

	}

	public static char verifyKeyStore(String user, String password) {
		char flag = 'o';
		try {
			FileInputStream kfile = new FileInputStream(user + ".keystore");
			KeyStore kstore = KeyStore.getInstance("PKCS12");
			kstore.load(kfile, password.toCharArray());
		} catch (FileNotFoundException e) {
			flag = 'f';
		} catch (IOException e) {
			flag = 'p';
		} catch (Exception e) {
			flag = 'e';
		}
		return flag;
	}

	public static char verifyCertificate(String user, String medico, String password) {
		char flag = 'o';
		try {
			FileInputStream kfile = new FileInputStream(medico + ".keystore");
			KeyStore kstore = KeyStore.getInstance("PKCS12");
			kstore.load(kfile, password.toCharArray());
			try {
				PublicKey publicKey = kstore.getCertificate(user).getPublicKey();
			} catch (Exception e) {
				System.out.println("	\u001B[31m»» Cannot get the certificate of the user: " + user + "!\u001B[0m");
				flag = 'c';
			}
		} catch (FileNotFoundException e) {
			flag = 'f';
		} catch (IOException e) {
			flag = 'p';
		} catch (Exception e) {
			flag = 'e';
		}

		return flag;
	}

	public static byte[] generateSalt() {
		// Gerar um salt aleatório
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[16];
		random.nextBytes(salt);
		return salt;
	}

	public static String hashPassword(String password, byte[] salt) {
		try {

			// Criar uma instância do MessageDigest para SHA-256
			MessageDigest digest = MessageDigest.getInstance("SHA-256");

			// Adicionar o salt aos bytes da senha
			byte[] passwordBytes = password.getBytes();
			byte[] saltedPasswordBytes = new byte[passwordBytes.length + salt.length];
			System.arraycopy(passwordBytes, 0, saltedPasswordBytes, 0, passwordBytes.length);
			System.arraycopy(salt, 0, saltedPasswordBytes, passwordBytes.length, salt.length);

			// Aplicar o digest nos bytes da senha + salt
			byte[] hashedBytes = digest.digest(saltedPasswordBytes);

			// Concatenar salt e senha hash em um formato seguro para armazenamento
			String hashedPassword = bytesToHex(hashedBytes);
			String saltString = bytesToHex(salt);

			String storedPassword = hashedPassword;
			return storedPassword;

		} catch (NoSuchAlgorithmException e) {
			// Tratar caso o algoritmo não seja suportado
			e.printStackTrace();
			return null;
		}
	}

	public static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

	public Boolean importCert(String userAuth, String userCert, String password) {
		try {

			Boolean ver = (Boolean) sc.recieveContent();

			if (ver) {
				// receber o cert do server
				String filePath = (String) sc.recieveContent();
				long fileSize = (long) sc.recieveContent();

				FileOutputStream fos = new FileOutputStream(filePath);
				BufferedOutputStream bos = new BufferedOutputStream(fos);

				byte[] buffer = new byte[1024];
				int bytesRead;

				while (fileSize > 0
						&& (bytesRead = sc.read(buffer, 0, (int) Math.min(buffer.length, fileSize))) != -1) {

					bos.write(buffer, 0, bytesRead);
					fileSize -= bytesRead;
				}

				bos.flush();
				bos.close();
				Arrays.fill(buffer, (byte) 0);

				// import certificado
				KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
				keystore.load(new FileInputStream(userAuth + ".keystore"), password.toCharArray());

				FileInputStream cfis = new FileInputStream(filePath);
				Certificate cert = java.security.cert.CertificateFactory.getInstance("X.509")
						.generateCertificate(cfis);
				cfis.close();

				keystore.setCertificateEntry(userCert, cert);

				// atualizar keystore
				keystore.store(new FileOutputStream(userAuth + ".keystore"), password.toCharArray());
				System.out.println("====================================\nImport Certificate Status:");
				System.out.println("	\u001B[32m»» The certificate of that user was imported from the server\u001B[0m");
				return true;
			} else {
				System.out.println("====================================\nImport Certificate Status:");
				System.out.println("	\u001B[31m»» There is no certificate for that user on the server\u001B[0m");
				return false;
			}

		} catch (Exception e) {
			e.printStackTrace();
			return true;
		}

	}

	public static void generateMAC(SecretKey key) {
		try {
			FileOutputStream fos = new FileOutputStream("users.mac");
			FileInputStream fis = new FileInputStream("users.txt");

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);
			byte[] b = new byte[256];
			int i = fis.read();
			while (i != -1) {
				mac.update(b, 0, i);
				i = fis.read(b);
			}

			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(mac.doFinal());
			oos.close();
			fos.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static boolean verifyMAC(SecretKey key) {
		try {
			FileInputStream fis = new FileInputStream("users.mac");
			FileInputStream fis1 = new FileInputStream("users.txt");

			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(key);

			byte[] b = new byte[256];
			int i = fis1.read();
			while (i != -1) { // porque não limitado à dimensão de byte[] do java
				mac.update(b, 0, i);
				i = fis1.read(b);
			}

			ObjectInputStream ois = new ObjectInputStream(fis);
			byte[] mac1 = (byte[]) ois.readObject();
			ois.close();
			fis.close();

			byte[] mac2 = mac.doFinal();

			return Arrays.equals(mac1, mac2);

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return false;
		}
	}

}