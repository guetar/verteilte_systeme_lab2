package proxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
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

import util.ChecksumUtils;
import util.ComponentFactory;
import util.Config;
import cli.Command;
import cli.Shell;
import message.Response;
import message.request.BuyRequest;
import message.request.CreditsRequest;
import message.request.DownloadTicketRequest;
import message.request.InfoRequest;
import message.request.ListRequest;
import message.request.LoginRequest;
import message.request.LogoutRequest;
import message.request.UploadRequest;
import message.request.VersionRequest;
import message.response.BuyResponse;
import message.response.CreditsResponse;
import message.response.DownloadTicketResponse;
import message.response.FileServerInfoResponse;
import message.response.InfoResponse;
import message.response.ListResponse;
import message.response.LoginResponse;
import message.response.MessageResponse;
import message.response.LoginResponse.Type;
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
	} catch (Exception exc) {
	    System.out.println(exc.getMessage());
	}

	shell.register(this);

	shellThread = new Thread(shell);
	shellThread.start();

	// getThreadExecutor().execute(shell);
	getThreadExecutor().execute(new ProxySocket(tcpPort));
	getThreadExecutor().execute(new ProxyDatagramSocket(udpPort));

	timer.schedule(new Alive(), checkPeriod, checkPeriod);
    }

    private void validateConfig(Config config) throws Exception {
	try {
	    tcpPort = config.getInt("tcp.port");
	    udpPort = config.getInt("udp.port");
	    timeout = config.getInt("fileserver.timeout");
	    checkPeriod = config.getInt("fileserver.checkPeriod");
	} catch (Exception exc) {
	    throw new Exception("client.properties invalid");

	}

	try {
	    InputStream inUserProperties = ClassLoader
		    .getSystemResourceAsStream("user.properties");

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
	} catch (Exception exc) {
	    throw new Exception("user.properties invalid");

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
		    String input = new String(packet.getData(), 0,
			    packet.getLength());
		    String[] splitArray = input.split(" ");
		    long last = System.currentTimeMillis();
		    port = Integer.parseInt(splitArray[2]);
		    address = InetAddress.getByName(splitArray[1]);
		    dir = splitArray[3];

		    if (!isAlive.containsKey(splitArray[2])) {
			isAlive.put(splitArray[2], "online");
			FServer.addFileServertoList(new FServer(dir, port,
				address));
		    } else if (isAlive.containsKey(splitArray[2])) {
			for (FServer fileServer : FServer.getFileServerList()) {
			    if (fileServer.getTcpPort() == port) {
				if (fileServer.isOnline() == true) {
				    fileServer.setLastTime(last);
				    break;
				} else if (fileServer.isOnline() == false) {
				    isAlive.remove(splitArray[2]);
				    isAlive.put(splitArray[2], "online");
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

		    if (fileServer.isOnline() == true) {
			if (time > Proxy.timeout) {
			    fileServer.setOnline(false);
			    ProxyDatagramSocket.isAlive.put(
				    String.valueOf(fileServer.getTcpPort()),
				    "offline");
			}
		    }
		}
	    }
	}
    }

    public class ProxySocket implements Runnable {

	int tcpPort;

	public ProxySocket(int tcpPort) {
	    this.tcpPort = tcpPort;
	}

	public void run() {
	    try {
		proxySocket = new ServerSocket(tcpPort);
	    } catch (IOException e) {
		System.out.println("Error creating a Thread.");
	    }
	    try {
		while (true) {
		    getThreadExecutor().execute(
			    new ProxySocketThread(proxySocket.accept()));
		}
	    } catch (IOException e) {
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
	int credits;
	String download;
	String checksum = "checksum";
	InetAddress address;
	Set<String> listFiles = new HashSet<String>();

	public ProxySocketThread(Socket socket) {
	    this.socket = socket;
	}

	public void run() {
	    try {
		reader = new ObjectInputStream(socket.getInputStream());
		writer = new ObjectOutputStream(socket.getOutputStream());

		Object inputObject = null;

		while (true) {
		    try {
			inputObject = reader.readObject();

			if (inputObject instanceof LoginRequest) {
			    writer.writeObject(login((LoginRequest) inputObject));
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
			writer.writeObject(new MessageResponse(
				"Fehlerhafte Request"));
		    } catch (IOException exc) {
			writer.writeObject(new MessageResponse(exc.getMessage()));
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
	    } catch (Exception exc) {

	    }
	    try {
		readerFileServer.close();
	    } catch (Exception exc) {

	    }

	    try {
		isSocketFileServer.close();
	    } catch (Exception exc) {

	    } finally {
		isSocketFileServer = null;
	    }

	    try {
		osSocketFileServer.close();
	    } catch (Exception exc) {

	    } finally {
		osSocketFileServer = null;
	    }

	    try {
		socketFileServer.close();
	    } catch (Exception exc) {

	    } finally {
		socketFileServer = null;
	    }
	}

	public Object getResponse(Object request) {
	    Object responseObject = null;

	    try {
		writerFileServer.writeObject(request);
		writerFileServer.flush();

		while (true) {
		    responseObject = readerFileServer.readObject();
		    return responseObject;
		}

	    } catch (IOException e) {
		
	    } catch (ClassNotFoundException e) {
		
	    }

	    return responseObject;
	}

	@Override
	public LoginResponse login(LoginRequest request) throws IOException {
	    loggedInUser = request.getUsername();
	    LoginResponse response = new LoginResponse(Type.WRONG_CREDENTIALS);

	    for (User user : User.getUserList()) {
		if (user.getName().equals(loggedInUser)) {
		    if (user.getPassword().equals(request.getPassword())) {
			if (!user.isOnline()) {
			    user.setOnline(true);
			    loggedIn = true;
			    response = new LoginResponse(Type.SUCCESS);
			} else {
			    throw new IOException("User already logged in!");
			}
		    }
		    break;
		}
	    }
	    return response;
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

	    if (loggedIn == true) {
		for (FServer fileServer : FServer.getFileServerList()) {
		    if(fileServer.isOnline() == true){
			try {
				openConnection(fileServer.getAddress(),
					fileServer.getTcpPort());
			    } catch (Exception e) {

			    }
			    Object responseObject = getResponse(new ListRequest());

			    if (responseObject instanceof ListResponse) {

				fileServer.setListFiles(((ListResponse) responseObject)
					.getFileNames());
				for (String fileName : ((ListResponse) responseObject)
					.getFileNames()) {
				    if (!!listFiles.contains(fileName)) {
					listFiles.add(fileName);
				    }
				}
				response = new ListResponse(
					((ListResponse) responseObject).getFileNames());
			    }
			    closeConnection();
			}
		    }
		    
	    } else {
		response = new MessageResponse("You have to log in first.");
	    }
	    return response;
	}

	@Override
	public Response download(DownloadTicketRequest request)
		throws IOException {

	    int port = 0;
	    long usage = 0;
	    long lowest = 0;
	    String fileName = request.getFilename();
	    list();
	    long filesize = 0;
	    int version = 0;
	    boolean file = false;
	    Response response = new MessageResponse("File not available.");

	    if (loggedIn == true) {

		for (FServer fileServer : FServer.getFileServerList()) {
		    if (fileServer.getListFiles().contains(fileName) && fileServer.isOnline() == true) {

			try {
			    openConnection(fileServer.getAddress(),
				    fileServer.getTcpPort());
			} catch (Exception e) {

			}
			InfoResponse responseObject = (InfoResponse) getResponse(new InfoRequest(
				fileName));
			filesize = responseObject.getSize();
			file = true;
			break;
		    } else {
			file = false;
			new MessageResponse("File not available.");
		    }
		}

		if (file == true) {
		    for (User user : User.getUserList()) {
			if (user.getName().equals(loggedInUser)) {
			    if (user.getCredits() >= filesize) {
				VersionResponse responseObject = (VersionResponse) getResponse(new VersionRequest(
					fileName));
				for (FServer fileServer : FServer
					.getFileServerList()) {
				    if (fileServer.isOnline() == true) {
					if (fileServer.getListFiles().contains(
						fileName)) {
					    usage = fileServer.getUsage();
					    if (lowest == 0) {
						lowest = usage;
						address = fileServer
							.getAddress();
						port = fileServer.getTcpPort();
						version = responseObject
							.getVersion();
					    } else if ((usage < lowest)
						    && (responseObject
							    .getVersion() >= version)) {
						lowest = usage;
						address = fileServer
							.getAddress();
						port = fileServer.getTcpPort();
						version = responseObject
							.getVersion();
					    }
					}
				    }
				}

				for (FServer fileServer : FServer
					.getFileServerList()) {
				    if (fileServer.getTcpPort() == port) {
					long newUsage = usage + filesize;
					fileServer.setUsage(newUsage);
					break;
				    }
				}

				long newCredits = user.getCredits() - filesize;
				user.setCredits(newCredits);

				checksum = ChecksumUtils.generateChecksum(
					loggedInUser, fileName, version,
					filesize);

				DownloadTicket ticket = new DownloadTicket(
					loggedInUser, fileName, checksum,
					address, port);
				response = new DownloadTicketResponse(ticket);
				closeConnection();
			    } else {
				response = new MessageResponse(
					"Not enough credits!");
				closeConnection();
				break;
			    }
			}
		    }
		}
	    } else {
		response = new MessageResponse("You have to log in first.");
	    }
	    return response;
	}

	@Override
	public MessageResponse upload(UploadRequest request) throws IOException {
	    list();
	    String fileName = request.getFilename();
	    int version = 0;
	    byte[] content = request.getContent();
	    long filesize = 0;
	    MessageResponse response = new MessageResponse("success");

	    if (loggedIn == true) {

		for (FServer fileServer : FServer.getFileServerList()) {
		    if(fileServer.isOnline()==true){
			try {
				openConnection(fileServer.getAddress(),
					fileServer.getTcpPort());
			    } catch (Exception e) {

			    }

			    InfoResponse infoResponseObject = (InfoResponse) getResponse(new InfoRequest(
				    fileName));
			    filesize = infoResponseObject.getSize();

			    VersionResponse versionResponseObject = (VersionResponse) getResponse(new VersionRequest(
				    fileName));
			    version = versionResponseObject.getVersion();

			    MessageResponse responseObject = (MessageResponse) getResponse(new UploadRequest(
				    fileName, version, content));

			    closeConnection();
		    }
		}

		for (User user : User.getUserList()) {
		    if (user.getName().equals(loggedInUser)) {

			long newCredits = user.getCredits() + filesize
				+ filesize;
			user.setCredits(newCredits);
			break;
		    }
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
	    fileServerInfoList.add(new FileServerInfo(fileServer.getAddress(),
		    fileServer.getTcpPort(), fileServer.getUsage(), fileServer
			    .isOnline()));
	}
	return new FileServerInfoResponse(fileServerInfoList);
    }

    @Command
    public UserInfoResponse users() throws IOException {
	List<UserInfo> userInfoList = new ArrayList<UserInfo>();

	for (User user : User.getUserList()) {
	    userInfoList.add(new UserInfo(user.getName(), user.getCredits(),
		    user.isOnline()));
	}
	return new UserInfoResponse(userInfoList);
    }

    @Command
    public MessageResponse exit() throws IOException {
	timer.cancel();

	if(proxySocket != null){
	    try {
		proxySocket.close();
	    } catch (Exception exc) {

	    } finally {
		proxySocket = null;
	    }
	}
	
	if(proxyDatagramSocket != null){
	    try {
		proxyDatagramSocket.close();
	    } catch (Exception exc) {

	    } finally {
		proxyDatagramSocket = null;
	    }
	}
	
	
	
//	try {
//	    proxySocket.close();
//	} catch (Exception e) {
//
//	}
//
//	try {
//	    proxyDatagramSocket.close();
//	} catch (Exception e) {
//
//	}

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
