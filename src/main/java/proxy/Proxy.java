package proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Collections;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;

import security.SecurityAspect;
import util.ChecksumUtils;
import util.ComponentFactory;
import util.Config;
import cli.Command;
import cli.Shell;
import message.Request;
import message.Response;
import message.request.BuyRequest;
import message.request.CreditsRequest;
import message.request.DownloadFileRequest;
import message.request.DownloadTicketRequest;
import message.request.HmacRequest;
import message.request.InfoRequest;
import message.request.ListRequest;
import message.request.LoginRequestFirst;
import message.request.LoginRequestSecond;
import message.request.LogoutRequest;
import message.request.UploadRequest;
import message.request.VersionRequest;
import message.response.BuyResponse;
import message.response.CreditsResponse;
import message.response.DownloadFileResponse;
import message.response.DownloadTicketResponse;
import message.response.FileServerInfoResponse;
import message.response.HmacResponse;
import message.response.InfoResponse;
import message.response.ListResponse;
import message.response.LoginResponse;
import message.response.MessageResponse;
import message.response.UserInfoResponse;
import message.response.VersionResponse;
import model.DownloadTicket;
import model.FileServerInfo;
import model.UserInfo;

public class Proxy implements IProxyCli {
	private final Config config;
	private final Shell shell;
	private Thread shellThread = null;
	private Config configUser;
	
	private int tcpPort = 0;
	private int udpPort;
	private static long timeout;
	private int checkPeriod;
	private String proxyPrivateKeyPath = null;
	private String hmacKey;
	
	
	private PrivateKey privateKey = null;
	

	Timer timer = new Timer();

	private static ExecutorService threadExecutor;

	static HashSet<String> userkeys = null;

	private static DatagramSocket proxyDatagramSocket;
	private ServerSocket proxySocket;

	public Proxy() throws Exception {
		this.config = new Config("proxy");
		this.shell = new Shell("proxy", System.out, System.in);
		new Proxy(config, shell);
	}

	public Proxy(final Config config, final Shell shell) throws Exception {
		threadExecutor = Executors.newCachedThreadPool();
		this.config = config;
		this.shell = shell;
		this.configUser = new Config("user");

		if (config == null) {
			throw new IllegalArgumentException();
		}

		try {
			validateConfig(config);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}

		shell.register(this);

		shellThread = new Thread(shell);
		shellThread.start();

		// getThreadExecutor().execute(shell);
		getThreadExecutor().execute(new ProxySocket(tcpPort, hmacKey));
		getThreadExecutor().execute(new ProxyDatagramSocket(udpPort));

		timer.schedule(new Alive(), checkPeriod, checkPeriod);
		
		privateKey = SecurityAspect.getInstance().readPrivateKey(proxyPrivateKeyPath,"12345");
	}

	private void validateConfig(Config config) throws Exception {
		
		tcpPort = config.getInt("tcp.port");
		udpPort = config.getInt("udp.port");
		timeout = config.getInt("fileserver.timeout");
		checkPeriod = config.getInt("fileserver.checkPeriod");
			proxyPrivateKeyPath = config.getString("key");
		hmacKey = config.getString("hmac.key");
		InputStream inUserProperties = ClassLoader.getSystemResourceAsStream("user.properties");

		if (inUserProperties != null) {
			Properties userProperties = new Properties();
			userProperties.load(inUserProperties);
			Enumeration<Object> keys = userProperties.keys();
			userkeys = new HashSet<String>();

			while (keys.hasMoreElements()) {
				String key = (String) keys.nextElement();
				String u = "";

				if (key.contains(".credits")) {
					u = key.replace(".credits", "");
				}
				if (key.contains(".password")) {
					u = key.replace(".password", "");
				}
				userkeys.add(u);
			}

			User.getUserList().clear();

			for (Iterator<String> it = userkeys.iterator(); it.hasNext();) {
				String user = it.next();
				int credits;
				String userPropertiesKey = user + ".credits";
				credits = configUser.getInt(userPropertiesKey);
				userPropertiesKey = user + ".password";
				String password;
				password = configUser.getString(userPropertiesKey);

				User.addUsertoList(new User(user, password, credits));
			}
		}
	}

	public Config getConfig() {
		return config;
	}

	public static class ProxyDatagramSocket implements Runnable {
		private int udpPort;
		private int port;
		private InetAddress address;
		private String dir;
		private DatagramPacket packet = null;
		public static Hashtable<String, String> isAlive = new Hashtable<String, String>();

		public ProxyDatagramSocket(int udpPort) {
			this.udpPort = udpPort;
		}

		@Override
		public void run() {
			try {
				proxyDatagramSocket = new DatagramSocket(udpPort);

				while (true) {
					byte[] buffer = new byte[256];
					packet = new DatagramPacket(buffer, buffer.length);
					proxyDatagramSocket.receive(packet);
					String input = new String(packet.getData(), 0, packet.getLength());
					String[] splitArray = input.split(" ");
					long last = System.currentTimeMillis();
					
					port = Integer.parseInt(splitArray[1]);
					address = InetAddress.getByName(splitArray[2]);
					dir = splitArray[3];

					if (!isAlive.containsKey(splitArray[1])) {
						isAlive.put(splitArray[1], "online");
						FServer.addFileServertoList(new FServer(dir, port, address));
					} else if (isAlive.containsKey(splitArray[1])) {
						for (FServer fileServer : FServer.getFileServerList()) {
							if (fileServer.getTcpPort() == port) {
								if (fileServer.isOnline() == true) {
									fileServer.setLastTime(last);
									break;
								} else if (fileServer.isOnline() == false) {
									isAlive.remove(splitArray[1]);
									isAlive.put(splitArray[1], "online");
									fileServer.setOnline(true);
									fileServer.setLastTime(last);
									break;
								}
							}
						}
					}
				}
			} catch (SocketException e) {

			} catch (IOException e) {
				System.out.println("Error datagram socket");
			} finally {
				if (proxyDatagramSocket != null) {
					proxyDatagramSocket.close();
				}
			}
		}
	}

	public class Alive extends TimerTask {

		@Override
		public void run() {
			long last = System.currentTimeMillis();
			long now = 0;
			long time = 0;

			if (!FServer.getFileServerList().isEmpty()) {
				for (FServer fileServer : FServer.getFileServerList()) {
					last = fileServer.getLastTime();
					now = System.currentTimeMillis();
					time = now - last;

					if (fileServer.isOnline() && time > Proxy.timeout) {
						fileServer.setOnline(false);
						ProxyDatagramSocket.isAlive.put(String.valueOf(fileServer.getTcpPort()), "offline");
					}
				}
			}
		}
	}

	public class ProxySocket implements Runnable {

		int tcpPort;
		Mac hMac;

		public ProxySocket(int tcpPort, String hmacKey) {
			this.tcpPort = tcpPort;
			try{
				Key secretKey = new SecretKeySpec(hmacKey.getBytes(), "HmacSHA256");

				hMac = Mac.getInstance("HmacSHA256");
				hMac.init(secretKey);
				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			}
		}

		public void run() {
			try {
				proxySocket = new ServerSocket(tcpPort);
			} catch (IOException e) {
				System.out.println("Error creating a Thread.");
			}
			try {
				while (true) {
					getThreadExecutor().execute(new ProxySocketThread(proxySocket.accept(), hMac));
				}
			} catch (IOException e) {
				// Occurs if socket is closed by !exit
			}
		}
	}

	public class ProxySocketThread implements Runnable, IProxy {
		private Socket socket = null;
		private ObjectOutputStream writer = null;
		private ObjectInputStream reader = null;

		private Socket socketFileServer = null;
		private InputStream isSocketFileServer = null;
		private OutputStream osSocketFileServer = null;
		private ObjectOutputStream writerFileServer = null;
		private ObjectInputStream readerFileServer = null;

		private String loggedInUser = null;
		private boolean loggedIn = false;
		private int credits;
		private Mac hMac;
		
		String download;
		String checksum = "checksum";
		InetAddress address;
		Set<String> listFiles = new HashSet<String>();
		
		private SecretKey secretKey = null;
		private byte[] ivparameter = null;
		private byte[] proxyChallenge = null;
		
		public ProxySocketThread(Socket socket, Mac hMac) {
		

			this.socket = socket;
			this.hMac = hMac;
		}

		public void run() {
			try {
				reader = new ObjectInputStream(socket.getInputStream());
				writer = new ObjectOutputStream(socket.getOutputStream());

				Object inputObject = null;

				while (true) {
					try {
						inputObject = reader.readObject();

						if (inputObject instanceof LoginRequestFirst) {
							writer.writeObject(login((LoginRequestFirst) inputObject));
						} else if (inputObject instanceof LoginRequestSecond) {
							writer.writeObject(login((LoginRequestSecond) inputObject));
						} else if (inputObject instanceof LogoutRequest) {
							writer.writeObject(logout());
						} else if (inputObject instanceof CreditsRequest) {
							writer.writeObject(credits());
						} else if (inputObject instanceof BuyRequest) {
							writer.writeObject(buy((BuyRequest) inputObject));
						} else if (inputObject instanceof ListRequest) {
							writer.writeObject(list());
						} else if (inputObject instanceof DownloadTicketRequest) {
							writer.writeObject(download((DownloadTicketRequest) inputObject));
						} else if (inputObject instanceof UploadRequest) {
							writer.writeObject(upload((UploadRequest) inputObject));
						}
					} catch (ClassNotFoundException exc) {
						writer.writeObject(new MessageResponse("Fehlerhafter Request"));
					} catch (IOException exc) {
						writer.writeObject(new MessageResponse("Fehlerhafter Request"));
					}
				}
			} catch (IOException e) {
				
			} finally {
				try {
					writer.close();
					reader.close();
					socket.close();

				} catch (Exception exc) {

				}
			}
		}

		public void interrupt() {
			try {
				reader.close();
				writer.close();
				socket.close();
			} catch (Exception e) {

			}
		}

		private void openConnection(InetAddress address, int tcpPort)
				throws Exception {

			try {
				if (socketFileServer == null) {
					socketFileServer = new Socket(address, tcpPort);
					isSocketFileServer = socketFileServer.getInputStream();
					osSocketFileServer = socketFileServer.getOutputStream();
				}
			} catch (Exception exc) {
				throw new Exception(
						"Couldn't get I/O for connection to the host "
								+ address);
			}

			try {
				writerFileServer = new ObjectOutputStream(osSocketFileServer);
				readerFileServer = new ObjectInputStream(isSocketFileServer);
			} catch (IOException exc) {
				throw new Exception(
						"Couldn't initialize Object Input / Output Stream to the host "
								+ address);
			}
		}

		private void closeConnection() {
			try {
				writerFileServer.close();
				readerFileServer.close();
				isSocketFileServer.close();
				osSocketFileServer.close();
				socketFileServer.close();
			} catch (Exception exc) {

			} finally {
				isSocketFileServer = null;
				osSocketFileServer = null;
				socketFileServer = null;
			}
		}
		
		public boolean verifyHmac(HmacResponse response) {
			hMac.update(response.getResponse().toString().getBytes());
			byte[] computedHash = hMac.doFinal();
			byte[] receivedHash = Base64.decode(((HmacResponse) response).getHmac());
			return MessageDigest.isEqual(computedHash,receivedHash);
		}
		
		public Request hmacRequest(Request request) {
			hMac.update(request.toString().getBytes());
			byte[] hmac = Base64.encode(hMac.doFinal());
			return new HmacRequest(hmac, request);
		}

		public Response getResponse(Request request) {
			Response responseObject = null;

			try {
				writerFileServer.writeObject(hmacRequest(request));
				writerFileServer.flush();

				while (true) {
					responseObject = (Response) readerFileServer.readObject();
					if (responseObject instanceof HmacResponse && verifyHmac((HmacResponse) responseObject)) {
						return ((HmacResponse) responseObject).getResponse();
					} else {
						writer.writeObject(new MessageResponse("Fehlerhafte Response"));
						shell.writeLine(responseObject.toString());
					}
				}

			} catch (IOException e) {

			} catch (ClassNotFoundException e) {

			}

			return responseObject;
		}

		@Override
		public LoginResponse login(LoginRequestFirst request) throws IOException {
			
			SecurityAspect secure = SecurityAspect.getInstance();
			
			String message = request.getMessage();
			byte[] cipherMessage = secure.decodeBase64(message.getBytes());
			
			byte[] decryptedMessage = secure.decryptCipherRSA(cipherMessage, privateKey);
			
			String[] userMessage = new String(decryptedMessage).split(" ");
			
			if(!userMessage[0].equals("!login")) {
				return null;
			}
			
			Config c = new Config("proxy");
			String keysPath = c.getString("keys.dir");
			
			//generate parameter
			proxyChallenge = secure.getSecureRandomNumber(32);
			secretKey = secure.generateSecretKey(256);
			ivparameter = secure.getSecureRandomNumber(16);
			byte[] clientChallenge = secure.decodeBase64(userMessage[1].getBytes());
			
			//save username
			loggedInUser = request.getUsername();
			
			//init response
			LoginResponse response = new LoginResponse(secure.readPublicKey(keysPath,userMessage[1]), clientChallenge, proxyChallenge, secretKey, ivparameter);

			return response;
		}
		
		@Override
		public LoginResponse login(LoginRequestSecond request) throws IOException {
			SecurityAspect secure = SecurityAspect.getInstance();
			
			String message = request.getMessage();
			byte[] cipherMessage = secure.decodeBase64(message.getBytes());
			
			byte[] recievedMessage = secure.decryptCipherAES(cipherMessage, secretKey, ivparameter);
						
			if((new String(secure.encodeBase64(proxyChallenge))).equals(new String(recievedMessage))) {
				for (User user : User.getUserList()) {
					if (user.getName().equals(loggedInUser)) {
						
						if (!user.isOnline()) {
							user.setOnline(true);
							loggedIn = true;
						} else {
							throw new IOException("User already logged in!");
						}
						
						break;
					}
				}
			} else {
				//user sent wrong message back
			}
			
			
			
			return null;
		}

		@Override
		public Response credits() throws IOException {
			Response response = null;

			if (loggedIn == true) {
				for (User user : User.getUserList()) {
					if (user.getName().equals(loggedInUser)) {
						long credits = user.getCredits();
						response = new CreditsResponse(credits);
					}
				}
			} else {
				response = new MessageResponse("You have to log in first.");
			}
			return response;
		}

		@Override
		public Response buy(BuyRequest request) throws IOException {
			Response response = null;
			long newCredits = 0;

			if (loggedIn == true) {
				for (User user : User.getUserList()) {
					if (user.getName().equals(loggedInUser)) {
						long credits = user.getCredits();
						newCredits = credits + request.getCredits();
						user.setCredits(newCredits);
						response = new BuyResponse(newCredits);
					}
				}
			} else {
				response = new MessageResponse("You have to log in first.");
			}
			return response;
		}

		@Override
		public Response list() throws IOException {
			Response response = null;

			if (loggedIn) {
				for (FServer fileServer : FServer.getFileServerList()) {
					if (fileServer.isOnline() == true) {
						try {
							openConnection(fileServer.getAddress(), fileServer.getTcpPort());
							Response responseObject = getResponse(new ListRequest());

							if (responseObject instanceof ListResponse) {

								fileServer.setListFiles(((ListResponse) responseObject).getFileNames());
								for (String fileName : ((ListResponse) responseObject).getFileNames()) {
									if(!listFiles.contains(fileName)) {
										listFiles.add(fileName);
									}
								}
							}
							closeConnection();
							
						} catch (Exception e) {

						}
					}
				}
				response = new ListResponse(listFiles);

			} else {
				response = new MessageResponse("You have to log in first.");
			}
			return response;
		}

		@Override
		public Response download(DownloadTicketRequest request) throws IOException {
			
			String fileName = request.getFilename();
			Response response = new MessageResponse("File not available.");

			list();
			FServer downloadServer = null;
			int version = -1;
			long fileSize = 0;
            
            // Calculate upload quorum
			int total = FServer.getFileServerList().size();
			int nw = (int) Math.floor(total / 2) + 1;
			int nr = total - nw;
            int cnt = 0;

			// Should not be necessary
			while (nw + nr <= total) {
				nr++;
			}

			if (loggedIn) {

                // Sort fileserverlist to get servers with minimum usage in front
                ArrayList<FServer> fileServerList = FServer.getFileServerList();
                Collections.sort(fileServerList);
                
                // Look for highest version
				for (FServer fileServer : fileServerList) {
					if (fileServer.isOnline()) {
                        
                        cnt++;
                        if (cnt > nr) break;
                        
						try {
							openConnection(fileServer.getAddress(), fileServer.getTcpPort());

							InfoResponse infoResponse = (InfoResponse) getResponse(new InfoRequest(fileName));
							fileSize = infoResponse.getSize();
                            VersionResponse versionResponse = (VersionResponse) getResponse(new VersionRequest(fileName));
                            if (versionResponse.getVersion() >= version) {
                                version = versionResponse.getVersion();
                                downloadServer = fileServer;
                            }
	                        closeConnection();
                            
						} catch (Exception e) {

						}
					}
				}

				if (downloadServer != null) {
					User user = User.getUser(loggedInUser);
					if (user != null && user.getCredits() >= fileSize) {
						
						try {
							openConnection(downloadServer.getAddress(), downloadServer.getTcpPort());
							
							String checksum = ChecksumUtils.generateChecksum(loggedInUser, fileName, version, fileSize);
							DownloadTicket ticket = new DownloadTicket(loggedInUser, fileName, checksum, downloadServer.getAddress(), downloadServer.getTcpPort());

							response = (DownloadFileResponse) getResponse(new DownloadFileRequest(ticket));
							
							downloadServer.setUsage(downloadServer.getUsage() + fileSize);
							user.setCredits(user.getCredits() - fileSize);
							
							closeConnection();
							
						} catch (Exception e) {

						}

					} else {
						response = new MessageResponse("Not enough credits!");
					}
				} else {
					response = new MessageResponse("File not available.");
				}
			} else {
				response = new MessageResponse("You have to log in first.");
			}
			return response;
		}

		@Override
		public MessageResponse upload(UploadRequest request) throws IOException {
			
			String fileName = request.getFilename();
			MessageResponse response = new MessageResponse("File could not be uploaded.");

			list();
			byte[] content = request.getContent();
			int version = -1;
			long fileSize = 0;
            
            // Calculate upload quorum
			int total = FServer.getFileServerList().size();
			int nw = (int) Math.floor(total / 2) + 1;
			int nr = total - nw;
            int cnt = 0;

			// Should not be necessary
			while (nw + nr <= total) {
				nr++;
			}

			if (loggedIn) {

                // Sort fileserverlist to get servers with minimum usage in front
                ArrayList<FServer> fileServerList = FServer.getFileServerList();
                Collections.sort(fileServerList);

                // Look for highest version
				for (FServer fileServer : fileServerList) {
					if (fileServer.isOnline()) {
                        
                        cnt++;
                        if (cnt > nr) break;
                        
						try {
							openConnection(fileServer.getAddress(), fileServer.getTcpPort());

		                	InfoResponse infoResponseObject = (InfoResponse) getResponse(new InfoRequest(fileName));
							fileSize = infoResponseObject.getSize();
                            VersionResponse versionResponse = (VersionResponse) getResponse(new VersionRequest(fileName));
                            
//							System.out.println("fileserver = " + fileServer.getDir() + " | files = " + fileServer.getListFiles().toString() + " | usage = " + fileServer.getUsage() + " | version = " + versionResponse.getVersion());
                            if (versionResponse.getVersion() >= version) {
                                version = versionResponse.getVersion();
                            }
	                        closeConnection();
                            
						} catch (Exception e) {

						}
					}
				}
				
				cnt = 0;
                //Upload file and update version
				for (FServer fileServer : fileServerList) {
					if (fileServer.isOnline()) {
                        
                        cnt++;
                        if (cnt > nw) break;
                        
                        try {
							openConnection(fileServer.getAddress(), fileServer.getTcpPort());

                            VersionResponse versionResponse = (VersionResponse) getResponse(new VersionRequest(fileName));
							response = (MessageResponse) getResponse(new UploadRequest(fileName, version, content));
							
//							System.out.println("fileserver = " + fileServer.getDir() + " | files = " + fileServer.getListFiles().toString() + " | usage = " + fileServer.getUsage() + " | version = " + versionResponse.getVersion());
							fileServer.setUsage(fileServer.getUsage() + fileSize);
							
							closeConnection();
							
						} catch (Exception e) {

						}
					}
                }

				User user = User.getUser(loggedInUser);
				if  (user != null) {
					 user.setCredits(user.getCredits() + fileSize * 2);
				}

			} else {
				response = new MessageResponse("You have to log in first.");
			}
			return response;
		}

		@Override
		public MessageResponse logout() throws IOException {
			MessageResponse response = new MessageResponse(
					"Successfully logged out.");
			if (loggedIn == true) {

				loggedIn = false;
				for (User user : User.getUserList()) {
					if (user.getName().equals(loggedInUser)) {
						user.setOnline(false);

						break;
					}
				}
			} else {
				response = new MessageResponse("You have to log in first.");
			}
			return response;
		}
	}

	@Command
	public FileServerInfoResponse fileservers() throws IOException {
		List<FileServerInfo> fileServerInfoList = new ArrayList<FileServerInfo>();

		for (FServer fileServer : FServer.getFileServerList()) {
			fileServerInfoList.add(new FileServerInfo(fileServer.getAddress(), fileServer.getTcpPort(), fileServer.getUsage(), fileServer.isOnline()));
		}
		return new FileServerInfoResponse(fileServerInfoList);
	}

	@Command
	public UserInfoResponse users() throws IOException {
		List<UserInfo> userInfoList = new ArrayList<UserInfo>();

		for (User user : User.getUserList()) {
			userInfoList.add(new UserInfo(user.getName(), user.getCredits(), user.isOnline()));
		}
		return new UserInfoResponse(userInfoList);
	}

	@Command
	public MessageResponse exit() throws IOException {
		timer.cancel();

		if (proxySocket != null) {
			try {
				proxySocket.close();
			} catch (Exception exc) {

			} finally {
				proxySocket = null;
			}
		}

		if (proxyDatagramSocket != null) {
			try {
				proxyDatagramSocket.close();
			} catch (Exception exc) {

			} finally {
				proxyDatagramSocket = null;
			}
		}

		// try {
		// proxySocket.close();
		// } catch (Exception e) {
		//
		// }
		//
		// try {
		// proxyDatagramSocket.close();
		// } catch (Exception e) {
		//
		// }

		try {
			threadExecutor.shutdownNow();
		} catch (Exception e) {

		}

		shellThread.interrupt();
		shell.close();

		try {
			System.in.close();
		} catch (Exception exc) {
			// Do nothing
		}

		return new MessageResponse("Connection terminated!");
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			ComponentFactory componentFactory = new ComponentFactory();
			componentFactory.startProxy(new Config("proxy"), new Shell("proxy",
					System.out, System.in));
		} catch (Exception exc) {
			exc.printStackTrace();
		}

	}

	public static ExecutorService getThreadExecutor() {
		return threadExecutor;
	}

	public static void setThreadExecutor(ExecutorService threadExecutor) {
		Proxy.threadExecutor = threadExecutor;
	}
}
