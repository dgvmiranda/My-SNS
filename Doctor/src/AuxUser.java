import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AuxUser {
	// metodo para criar file users.txt caso nao exiata

	public static void createUsersFile(String password) {
		String fileName = "users.txt";
		File file = new File(fileName);

		try {
			if (file.createNewFile()) {
				System.out.println("	\u001B[32m»» File '" + fileName + "' created successfully.\u001B[0m");

				byte[] salt = AuxCipher.generateSalt();
				String hashPass = AuxCipher.hashPassword(password, salt);
				// Escreve a senha no arquivo
				try (FileWriter writer = new FileWriter("users.txt", true)) {
					String saltString = AuxCipher.bytesToHex(salt);

					writer.write("admin" + ";" + saltString + ";" + hashPass + System.lineSeparator()); // Formato:
																										// username:password
				} catch (IOException e) {
					e.printStackTrace();
				}

				System.out.println("	\u001B[32m»» Password for admin set successfully.\u001B[0m");
			} else {

				System.out.println("	\u001B[33m»» File '" + fileName + "' already exists.\u001B[0m");
			}
		} catch (IOException e) {
			System.out.println(
					"	\u001B[31m»» An error occurred while creating the file: " + e.getMessage() + "\u001B[0m");
		}

	}

	// Método estático para adicionar user
	public static void addUser(String username, String password, String salt) {

		try (FileWriter writer = new FileWriter("users.txt", true)) {
			writer.write(username + ";" + salt + ";" + password + System.lineSeparator());

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static boolean passwordAuthentication(String storedPassword, String providedPassword, String saltString) {
		try {
			boolean isValid = false;

			// Converter a string hexadecimal do salt de volta para bytes
			byte[] salt = hexStringToByteArray(saltString);

			String pass = AuxCipher.hashPassword(providedPassword, salt);

			byte[] passBytes = pass.getBytes();
			byte[] storedHashBytes = storedPassword.getBytes();

			// Comparar os hashes
			isValid = MessageDigest.isEqual(storedHashBytes, passBytes);
			System.out.println(
					isValid ? "	\u001B[32m»» Authentication successful\u001B[0m"
							: "	\u001B[31m»» Authentication failed\u001B[0m");

			return isValid;

		} catch (Exception e) {
			// Tratar outros erros
			e.printStackTrace();
			return false;
		}
	}

	// converte uma string hexadecimal em um array de bytes
	public static byte[] hexStringToByteArray(String hexString) {
		int len = hexString.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
					+ Character.digit(hexString.charAt(i + 1), 16));
		}
		return data;
	}

	public static Boolean authentication(String username, String providedPassword) {
		System.out.println("====================================\nAuthentication user:");
		Boolean valid = false;
		String saltString = null;
		String storedPassword = null;
		try {

			// String[] userInfo = getUser(username);
			String[] userInfo = getUserFromFile(username);
			if (userInfo != null) {
				saltString = userInfo[1];
				storedPassword = userInfo[2];
				valid = AuxUser.passwordAuthentication(storedPassword, providedPassword, saltString);
			} else {
				System.out.println("	\u001B[31m»» User not found\u001B[0m");
			}

			return valid;

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static String[] getUserFromFile(String username) {

		try (BufferedReader br = new BufferedReader(new FileReader("users.txt"))) {
			String line;
			while ((line = br.readLine()) != null) {
				String[] parts = line.split(";");
				if (parts.length == 3 && parts[0].equals(username)) {
					return parts;
				} else if (parts.length != 3) {
					System.out.println("Linha inválida: " + line);
				}
			}
		} catch (IOException e) {
			System.out.println("Erro ao ler o arquivo: " + e.getMessage());
		}
		return null;
	}

	public static boolean verifyCert(String username, ObjectOutputStream out) {

		String filename = username + ".crt";
		File file = new File("files/certs/" + filename);

		if (file.exists()) {
			try {

				out.writeObject(true);

				out.writeObject(file.getName());
				out.writeObject(file.length());

				FileInputStream fisc = new FileInputStream(file);

				byte[] bic = new byte[256];
				int kc = fisc.read(bic);
				while (kc != -1) {
					out.write(bic, 0, kc);
					kc = fisc.read(bic);
				}
				out.flush();
				fisc.close();

			} catch (Exception e) {
				System.out.println(e);
			}
			return true;

		} else {
			try {
				out.writeObject(false);
			} catch (Exception e) {
				System.out.println(e);
			}
			return false;
		}

	}

	public static SecretKey genSecretKeyMac(String password) {
		SecretKey key = null;
		try {
			PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
			key = kf.generateSecret(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return key;
	}
}