import java.io.*;
import java.util.*;

/**
 * client program
 */
public class mySNS {

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		Map<String, List<String>> argsFiltred = argsFilter(args);
		if (argsCheck(argsFiltred) == 'r') {
			return;
		}
		String password = null;
		String medico = null;
		String username = null;
		// Cria a conexão
		String[] address = addressFilter(argsFiltred.get("-a").get(0));
		cConnection sc = new cConnection(address[0], address[1]);

		if (!argsFiltred.containsKey("-au")) {
			username = argsFiltred.get("-u").toArray()[0].toString();
			password = argsFiltred.get("-p").toArray()[0].toString();
		} else {
			username = argsFiltred.get("-au").toArray()[0].toString();
			password = argsFiltred.get("-au").toArray()[1].toString();

		}
		if (!argsFiltred.containsKey("-g") && !argsFiltred.containsKey("-au")) {
			medico = argsFiltred.get("-m").toArray()[0].toString();
			// password = argsFiltred.get("-p").toArray()[1].toString();//???
		}
		// if (!sc.connect()) {
		// return;
		// }
		// Object serverCertification = sc.recieveContent();
		// if ("false".equals(serverCertification)){
		// System.out.println("Server compromised!");
		// }

		// OPCAO -au -> CRIA USER
		if (argsFiltred.containsKey("-au")) {

			if (!sc.connect()) {
				return;
			}
			try {
				sc.sendContent("-au");
				sc.sendContent(medico);
				sc.sendContent(username);
				sc.sendContent(password);

				char flagMac = (char) sc.recieveContent();
				if (flagMac == 'f') {
					System.out.println("====================================\nServer Status:");
					System.out.println(
							"	\u001B[31m»» Server shutdown! Check server for error or contact admin\u001B[0m");
					System.exit(0);
				}

				Object validation = sc.recieveContent();

				System.out.println("====================================\nCreate User:");
				if ("false".equals(validation)) {
					System.out.println("	\u001B[31m»» Username: " + username + "  already exist!\u001B[0m");
					System.exit(0);
				} else {
					System.out.println(
							"	\u001B[32m»» New username: " + username + " was created successfully!\u001B[0m");

				}

				sc.sendContent(1);
				List<String> auValues = argsFiltred.get("-au");
				String certFile = auValues.get(2);
				String[] certFiles = new String[1];
				certFiles[0] = certFile;

				sc.sendContent(username);
				sc.sendContent(certFiles);
				boolean verify = (boolean) sc.recieveContent();
				if (verify) {
					System.out.print(
							"	\u001B[33m»» File: " + certFile
									+ " was already saved in the server.\n\u001B[0m");
					System.out.print(
							"	\u001B[33m»» This operation would create duplicated files in the server.\n\u001B[0m");
					System.exit(0);

				}
				File file = new File(certFile);
				// envio size file original
				long sizefile = file.length();
				sc.sendContent(sizefile);
				sc.sendFile(certFile);
			} catch (Exception e) {
				System.out.println("	\u001B[31m»» A operacao nao teve sucesso,tente novamente.\u001B[0m");
				e.printStackTrace();
			}

		} else {

			if (!sc.connect()) {
				return;
			}

			// OPCAO -sc -> HIBRIDA
			if (argsFiltred.containsKey("-sc")) {
				if (!sc.connect()) {
					return;
				}
				sc.sendContent("-sc");
				sc.sendContent(medico);
				sc.sendContent(username);
				sc.sendContent(password);

				char flagMac = (char) sc.recieveContent();
				if (flagMac == 'f') {
					System.out.println("====================================\nServer Status:");
					System.out.println(
							"	\u001B[31m»» Server shutdown! Check server for error or contact admin\u001B[0m");
					System.exit(0);
				}

				Object validation = sc.recieveContent();

				System.out.println("====================================\nAuthentication user:");
				if ("false".equals(validation)) {
					System.out.println("	\u001B[31m»» Authentication Failed!\u001B[0m");
					System.exit(0);
				} else {
					System.out.println("	\u001B[32m»» Authentication Successfully!\u001B[0m");

				}
				// // recebe a password do keystore
				// Scanner sca = new Scanner(System.in);
				// System.out.print("Enter password for doctor keystore: ");
				// String pass = sca.nextLine();
				// sca.close();

				char flag = AuxCipher.verifyKeyStore(medico, password);
				if (flag != 'o') {
					System.out.println("====================================\nKeystore check:");
					if (flag == 'f') {
						System.out.println("	\u001B[31m»» "+ medico +".keystore doesn't exist\u001B[0m");
					} else if (flag == 'p') {
						System.out.println("	\u001B[31m»» Wrong password to "+ medico +".keystore\u001B[0m");
					} else if (flag == 'e') {
						System.out.println("	\u001B[31m»» Could not load keystore\u001B[0m");
					}
					return;
				}

				boolean exist = true;
				List<String> filesUpdated = fileVerify(argsFiltred.get("-sc"));
				try {
					// Enviar a lista de strings
					System.out.println("====================================\nOperation Status:");
					sc.sendContent(filesUpdated.size());
					for (String file : filesUpdated) {
						AuxCipher hib = new AuxCipher("AES", file, username, medico, password, sc);

						String filenamecifra = file + ".cifrado";
						String chaveFile = file + ".chave_secreta." + username;
						String[] values = { filenamecifra, chaveFile };
						sc.sendContent(username);

						sc.sendContent(values);

						exist = hib.hybrid(".cifrado");
					}
					if (!exist) {
						System.out.println("	\u001B[32m»» Operacao efetuada com sucesso!\u001B[0m");
					}
				} catch (Exception e) {
					System.out.println("	\u001B[31m»» A operacao nao teve sucesso,tente novamente.\u001B[0m");
					e.printStackTrace();
				}
			}

			// OPCAO -sa -> ASSINATURA
			if (argsFiltred.containsKey("-sa")) {

				// // recebe a password do keystore
				// Scanner sca = new Scanner(System.in);
				// System.out.print("Enter password for doctor keystore: ");
				// String pass = sca.nextLine();
				// sca.close();

				char flag = AuxCipher.verifyKeyStore(medico, password);
				if (flag != 'o') {
					System.out.println("====================================\nKeystore check:");
					if (flag == 'f') {
						System.out.println("	\u001B[31m»» "+ medico +".keystore doesn't exist\u001B[0m");
					} else if (flag == 'p') {
						System.out.println("	\u001B[31m»» Wrong password to "+ medico +".keystore\u001B[0m");
					} else if (flag == 'e') {
						System.out.println("	\u001B[31m»» Could not load keystore\u001B[0m");
					}
					return;
				}

				boolean exist = true;
				List<String> filesUpdated = fileVerify(argsFiltred.get("-sa"));
				try {
					if (!sc.connect()) {
						return;
					}
					sc.sendContent("-sa");
					sc.sendContent(medico);
					sc.sendContent(username);
					sc.sendContent(password);

					char flagMac = (char) sc.recieveContent();
					if (flagMac == 'f') {
						System.out.println("====================================\nServer Status:");
						System.out.println(
								"	\u001B[31m»» Server shutdown! Check server for error or contact admin\u001B[0m");
						System.exit(0);
					}

					Object validation = sc.recieveContent();

					System.out.println("====================================\nAuthentication user:");
					if ("false".equals(validation)) {
						System.out.println("	\u001B[31m»» Authentication Failed!\u001B[0m");
						System.exit(0);
					} else {
						System.out.println("	\u001B[32m»» Authentication Successfully!\u001B[0m");

					}

					System.out.println("====================================\nOperation Status:");
					sc.sendContent(filesUpdated.size()); // n files (n chamada aos metodos)

					for (String file : filesUpdated) {
						AuxCipher ass = new AuxCipher("AES", file, username, medico, password, sc);

						// nomes files a enviar
						String filenamecopy = file + ".assinado";
						String signatureFile = file + ".assinatura." + medico;
						String[] values = { filenamecopy, signatureFile };
						sc.sendContent(username);

						sc.sendContent(values);

						exist = ass.Signature();

					}
					if (!exist) {
						System.out.println("	\u001B[32m»» Operacao efetuada com sucesso!\u001B[0m");
					}
				} catch (Exception e) {
					System.out.println("	\u001B[31m»» A operacao nao teve sucesso,tente novamente.\u001B[0m");
					e.printStackTrace();
				}
			}

			// OPCAO -se -> ENVELOPE
			if (argsFiltred.containsKey("-se")) {

				// // recebe a password do keystore
				// Scanner sca = new Scanner(System.in);
				// System.out.print("Enter password for doctor keystore: ");
				// String pass = sca.nextLine();
				// sca.close();

				char flag = AuxCipher.verifyKeyStore(medico, password);
				if (flag != 'o') {
					System.out.println("====================================\nKeystore check:");
					if (flag == 'f') {
						System.out.println("	\u001B[31m»» "+ medico +".keystore doesn't exist\u001B[0m");
					} else if (flag == 'p') {
						System.out.println("	\u001B[31m»» Wrong password to "+ medico +".keystore\u001B[0m");
					} else if (flag == 'e') {
						System.out.println("	\u001B[31m»» Could not load keystore\u001B[0m");
					}
					return;
				}

				if (!sc.connect()) {
					return;
				}
				boolean exist = true;
				List<String> filesUpdated = fileVerify(argsFiltred.get("-se"));
				try {
					sc.sendContent("-se");
					sc.sendContent(medico);
					sc.sendContent(username);
					sc.sendContent(password);

					char flagMac = (char) sc.recieveContent();
					if (flagMac == 'f') {
						System.out.println("====================================\nServer Status:");
						System.out.println(
								"	\u001B[31m»» Server shutdown! Check server for error or contact admin\u001B[0m");
						System.exit(0);
					}

					Object validation = sc.recieveContent();
					System.out.println("====================================\nAuthentication user:");
					if ("false".equals(validation)) {
						System.out.println("	\u001B[31m»» Authentication Failed!\u001B[0m");
						System.exit(0);
					} else {
						System.out.println("	\u001B[32m»» Authentication Successfully!\u001B[0m");

					}

					System.out.println("====================================\nOperation Status:");
					sc.sendContent(filesUpdated.size() * 2);
					for (String file : filesUpdated) {
						AuxCipher env = new AuxCipher("AES", file, username, medico, password, sc);
						exist = env.envelope();
					}
					if (!exist) {
						System.out.println("	\u001B[32m»» Operacao efetuada com sucesso!\u001B[0m");
					}
				} catch (Exception e) {
					System.out.println("	\u001B[31m»» A operacao nao teve sucesso,tente novamente.\u001B[0m");
					e.printStackTrace();
				}
			}

			// OPCAO -g -> RECEBE FILES
			if (argsFiltred.containsKey("-g")) {

				char flag = AuxCipher.verifyKeyStore(username, password);
				if (flag != 'o') {
					System.out.println("====================================\nKeystore check:");
					if (flag == 'f') {
						System.out.println("	\u001B[31m»» "+ username +".keystore doesn't exist\u001B[0m");
					} else if (flag == 'p') {
						System.out.println("	\u001B[31m»» Wrong password to "+ username +".keystore\u001B[0m");
					} else if (flag == 'e') {
						System.out.println("	\u001B[31m»» Could not load keystore\u001B[0m");
					}
					return;
				}

				// cant verify cert aqui no medic name

				if (!sc.connect()) {
					return;
				}
				boolean exist = true;
				try {

					sc.sendContent("-g");
					sc.sendContent(medico);
					sc.sendContent(username);
					sc.sendContent(password);

					char flagMac = (char) sc.recieveContent();
					if (flagMac == 'f') {
						System.out.println("====================================\nServer Status:");
						System.out.println(
								"	\u001B[31m»» Server shutdown! Check server for error or contact admin\u001B[0m");
						System.exit(0);
					}

					Object validation = sc.recieveContent();
					System.out.println("====================================\nAuthentication user:");
					if ("false".equals(validation)) {
						System.out.println("	\u001B[31m»» Authentication Failed!\u001B[0m");
						System.exit(0);
					} else {
						System.out.println("	\u001B[32m»» Authentication Successfully!\u001B[0m");

					}

					System.out.println("====================================\nOperation Status:");
					sc.sendContent(argsFiltred.get("-g").size()); // n files
					for (String file : argsFiltred.get("-g")) {
						AuxCipher cyp = new AuxCipher("AES", file, username, null,
								password, sc);
						sc.sendContent(username);
						exist = cyp.verificG();
					}
					if (!exist) {
						System.out.println("	\u001B[32m»» Operacao efetuada com sucesso!\u001B[0m");
					}
				} catch (Exception e) {
					System.out.println("	\u001B[31m»» A operacao nao teve sucesso,tente novamente.\u001B[0m");
					e.printStackTrace();
				}
			}

		}
		sc.closeOutput();
		sc.closeInput();
		sc.close();
	}

	/*
	 * Function to deal with args
	 */
	public static Map<String, List<String>> argsFilter(String[] args) {
		Map<String, List<String>> argsFiltered = new HashMap<>();
		for (int i = 0; i < args.length; i++) {
			String option = args[i];
			if (option.equals("-a") || option.equals("-m") || option.equals("-u") || option.equals("-p")) {
				String argument = null;
				if (!args[i + 1].startsWith("-")) {
					argument = args[i + 1];
					i++;
				}
				List<String> values = new ArrayList<>();
				values.add(argument);
				argsFiltered.put(option, values);

			} else if (option.equals("-sc") || option.equals("-sa") || option.equals("-se") || option.equals("-g")) {
				List<String> files = new ArrayList<>();
				for (int j = i + 1; j < args.length && !args[j].startsWith("-"); j++) {
					files.add(args[j]);
				}
				if (files.size() <= 0) {
					files.add(null);
				}
				argsFiltered.put(option, files);
				i += files.size();
			} else if (option.equals("-au")) {
				List<String> auValues = new ArrayList<>();

				if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
					auValues.add(args[i + 1]); // username
					i++;

					if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
						auValues.add(args[i + 1]); // password
						i++;
					}
				}

				List<String> files = new ArrayList<>();

				for (int j = i + 1; j < args.length && !args[j].startsWith("-"); j++) {
					files.add(args[j]); // files
				}

				if (files.isEmpty()) {
					files.add(null);
				}

				auValues.addAll(files);
				argsFiltered.put(option, auValues);
				i += files.size() - 1;
			}
		}
		return argsFiltered;
	}

	/*
	 * function to see if all arguments are correct
	 */
	public static char argsCheck(Map<String, List<String>> args) {
		String cmdN = "\n	[-a] <address>\n	[-u] <username>\n [-u] <password>\n	 [-m] <medico>\n	[-sc|-sa|-se] <file1> <file2> ...";
		String cmdG = "\n	[-a] <address>\n	[-u] <username>\n	[-u] <password>\n  [-g] <file1> <file2> ...";
		String cmdC = "\n	[-a] <serverAddress>\n	[-au] <username> <password> <certificateFile>";

		Set<String> opt = args.keySet();
		if (opt.contains("-g")) {
			// options
			Set<String> optNeeded = new HashSet<String>();
			optNeeded.add("-a");
			optNeeded.add("-u");
			optNeeded.add("-g");
			optNeeded.add("-p");
			if (opt.equals(optNeeded)) {
				// arguments
				for (String argument : opt) {
					if (args.get(argument).get(0) == null) {
						System.out.println("Invalid command: Missing arguments!\n\nUsage with [-g]: " + cmdG
								+ "\n\nUsage with [-sc|-sa|-se]: " + cmdN);
						return 'r';
					}
				}
			} else if (opt.contains("-m")) {
				System.out.println("Invalid command: Option [-m] not used with [-g]!\n\nUsage with [-g]: " + cmdG
						+ "\n\nUsage with [-sc|-sa|-se]: " + cmdN);
				return 'r';
			} else {
				System.out.println("Invalid command: Missing options!\n\nUsage with [-g]: " + cmdG
						+ "\n\nUsage with [-sc|-sa|-se]: " + cmdN);
				return 'r';
			}

		} else if (opt.contains("-sc") || opt.contains("-sa") || opt.contains("-se")) {
			// options
			Set<String> optNeeded = new HashSet<String>();
			optNeeded.add("-a");
			optNeeded.add("-u");
			optNeeded.add("-m");
			optNeeded.add("-p");
			if (opt.contains("-sc")) {
				optNeeded.add("-sc");
			} else if (opt.contains("-sa")) {
				optNeeded.add("-sa");
			} else if (opt.contains("-se")) {
				optNeeded.add("-se");
			}
			if (opt.equals(optNeeded)) {
				// arguments
				for (String argument : opt) {
					if (args.get(argument).get(0) == null) {
						System.out.println("Invalid command: Missing arguments!\n\nUsage with [-g]: " + cmdG
								+ "\n\nUsage with [-sc|-sa|-se]: " + cmdN);
						return 'r';
					}
				}
			} else {
				System.out.println("Invalid command: Missing options!\n\nUsage with [-g]: " + cmdG
						+ "\n\nUsage with [-sc|-sa|-se]: " + cmdN);
				return 'r';
			}

		} else if (opt.contains("-au")) {
			Set<String> optNeeded = new HashSet<String>();
			optNeeded.add("-a");
			for (String argument : opt) {
				if (args.get(argument).isEmpty() || args.get(argument).get(0) == null) {
					System.out.println("Invalid command: Missing arguments!\n\nUsage: " + cmdC);
					return 'r';
				}
			}
		} else {
			System.out.println("Invalid command: Unknown option!\n\nUsage with [-g]: " + cmdG
					+ "\n\nUsage with [-sc|-sa|-se]: " + cmdN);
			return 'r';
		}

		return 'o';
	}

	/*
	 * Function to filter the files that exist
	 */
	public static List<String> fileVerify(List<String> files) {
		System.out.println("====================================\nFiles check:");
		List<String> filesUpdated = new ArrayList<>();
		Boolean ok = true;
		for (String file : files) {
			if (new File(file).isFile()) {
				filesUpdated.add(file);
			} else {
				ok = false;
				System.out.println("	\u001B[31m»» File: " + file + " doesn't exist!\u001B[0m");
			}
		}
		if (ok) {
			System.out.println("	\u001B[32m»» All files exist!\u001B[0m");
		}
		return filesUpdated;
	}

	/*
	 * Function to deal with address
	 */
	public static String[] addressFilter(String fullAddress) {
		return fullAddress.split(":");
	}
}