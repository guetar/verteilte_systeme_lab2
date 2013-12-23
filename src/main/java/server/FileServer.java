package server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import message.Response;
import message.request.DownloadFileRequest;
import message.request.InfoRequest;
import message.request.ListRequest;
import message.request.UploadRequest;
import message.request.VersionRequest;
import message.response.DownloadFileResponse;
import message.response.InfoResponse;
import message.response.ListResponse;
import message.response.MessageResponse;
import message.response.VersionResponse;
import model.DownloadTicket;

import cli.Command;
import cli.Shell;

import util.ChecksumUtils;
import util.ComponentFactory;
import util.Config;

public class FileServer implements IFileServerCli {

    private final Config config;
    private final Shell shell;
    private Thread shellThread = null;

    private ObjectOutputStream writer = null;
    private ObjectInputStream reader = null;

    private int tcpPort;
    private String proxyHost;
    private int udpPort;
    private int alive;
    private String dir;
    
    private Hashtable<String, Integer> versionList = new Hashtable<String, Integer>();
    private ServerSocket socket = null;
    private DatagramSocket datagramSocket;

    static ExecutorService threadExecutor;

    public FileServer(final Config config, final Shell shell) throws Exception {
		threadExecutor = Executors.newCachedThreadPool();
		this.config = config;
		this.shell = shell;
	
		if (config == null) {
		    System.out.println(config);
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
		
		//getThreadExecutor().execute(shell);
		getThreadExecutor().execute(new FileServerSocket(tcpPort));
		getThreadExecutor().execute(new sendIsAlive(tcpPort, proxyHost, udpPort, alive, dir));
    }

    private void validateConfig(Config config) throws Exception {
		try {
		    alive = config.getInt("fileserver.alive");
		    dir = config.getString("fileserver.dir");
		    tcpPort = config.getInt("tcp.port");
		    proxyHost = config.getString("proxy.host");
		    udpPort = config.getInt("proxy.udp.port");
		    System.out.println("fileserver = " + dir + " | tcpPort = " + tcpPort);
		} catch (Exception e) {
		    System.out.println("fs.properties invalid");
		}
    }

    public class FileServerSocket implements Runnable {
    	private int tcpPort;
	

		public FileServerSocket(int tcpPort) {
		    this.tcpPort = tcpPort;
		}
	
		@Override
		public void run() {
		    try {
			socket = new ServerSocket(tcpPort);
	
				while (true) {
				    getThreadExecutor().execute(new FileServerSocketThread(socket.accept()));
				}
		    } catch (IOException e) {
	
		    } finally {
				if(socket != null){
				    try {
					    socket.close();
					} catch (IOException e) {
		
					}
				}
		    }
		}
    }

    public class FileServerSocketThread implements Runnable, IFileServer {
		private Socket socket = null;
		private ObjectOutputStream writer = null;
		private ObjectInputStream reader = null;
	
		public FileServerSocketThread(Socket socket) {
		    this.socket = socket;
		}
	
		@Override
		public void run() {
		    Executors.newCachedThreadPool();
	
		    try {
			reader = new ObjectInputStream(socket.getInputStream());
			writer = new ObjectOutputStream(socket.getOutputStream());
	
			Object inputObject = null;
	
			while (true) {
			    try {
				inputObject = reader.readObject();
				if (inputObject instanceof ListRequest) {
				    writer.writeObject(list());
				} else if (inputObject instanceof DownloadFileRequest) {
				    writer.writeObject(download((DownloadFileRequest) inputObject));
				} else if (inputObject instanceof InfoRequest) {
				    writer.writeObject(info((InfoRequest) inputObject));
				} else if (inputObject instanceof VersionRequest) {
				    writer.writeObject(version((VersionRequest) inputObject));
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
			    reader.close();
			    writer.close();
			    socket.close();
			} catch (IOException e) {
	
			}
	    }
	}

	@Override
	public Response list() throws IOException {
	    Set<String> list = new HashSet<String>();
	    File folder;
	    File[] listOfFiles = null;

	    folder = new File(dir);
	    listOfFiles = folder.listFiles();
	    
	    if (listOfFiles.length > 0) {
			for (int i = 0; i < listOfFiles.length; i++) {
			    if (listOfFiles[i].isFile()) {
					list.add(listOfFiles[i].getName());
					if(!versionList.containsKey(listOfFiles[i].getName())) {
						versionList.put(listOfFiles[i].getName(), 0);
					}
			    }
			}
	    }
	    ListResponse response = new ListResponse(list);
	    return response;
	}

	@Override
	public Response download(DownloadFileRequest request) throws IOException {

	    DownloadFileResponse response = null;
	    DownloadTicket downloadTicket = request.getTicket();

	    String user = downloadTicket.getUsername();
	    String fileName = downloadTicket.getFilename();
	    File file = new File(dir + "/" + fileName);

	    int version = 0;
		if (versionList.containsKey(fileName)) {
		    version = versionList.get(fileName);
		}
		
	    String checksumfile = downloadTicket.getChecksum();
	    boolean checksum = ChecksumUtils.verifyChecksum(user, file, version, checksumfile);

	    if (checksum) {
			byte[] content = null;
			InputStream is = null;

			try {
			    content = new byte[(int) file.length()];
			    is = new FileInputStream(dir + "/" + downloadTicket.getFilename());
			    is.read(content);
	
			} finally {
			    is.close();
			}
	
			response = new DownloadFileResponse(downloadTicket, content);
	    }
	    return response;
	}

	@Override
	public Response info(InfoRequest request) throws IOException {
	    String filepath = request.getFilename();
	    File file = new File(dir + "/" + filepath);
	    long filesize = file.length();
	    InfoResponse response = new InfoResponse(filepath, filesize);

	    return response;
	}

	@Override
	public Response version(VersionRequest request) throws IOException {
	    String fileName = request.getFilename();

	    int version = -1;
	    if (versionList.containsKey(fileName)) {
		    version = versionList.get(fileName);
	    }
	    
	    VersionResponse response = new VersionResponse(fileName, version);
	    return response;
	}

	@Override
	public MessageResponse upload(UploadRequest request) throws IOException {
	    String fileName = request.getFilename();
	    byte[] content = request.getContent();
	    int version = request.getVersion();
	    
	    File file = new File(dir + "/" + fileName);

	    FileOutputStream fileWriter = new FileOutputStream(file);
	    fileWriter.write(content);
	    fileWriter.close();

	    if (versionList.containsKey(fileName)) {
		    versionList.remove(fileName);
	    }
	    versionList.put(fileName, version + 1);

	    return new MessageResponse("uploaded");
	}

    }

    public class sendIsAlive implements Runnable {
		private int tcpPort;
		private String proxyHost;
		private int udpPort;
		private long alive;
		private String dir;
		
	
		public sendIsAlive(int tcpPort, String proxyHost, int udpPort, long alive, String dir) {
		    this.tcpPort = tcpPort;
		    this.proxyHost = proxyHost;
		    this.udpPort = udpPort;
		    this.alive = alive;
		    this.dir = dir;
		}
	
		@Override
		public void run() {
		    try {
				datagramSocket = new DatagramSocket();
				InetAddress IPAddress = InetAddress.getByName(proxyHost);
				byte[] sendData = new byte[1024];
		
				String s = "!alive " + proxyHost + " " + tcpPort + " " + dir;
				sendData = s.getBytes();
		
				while (true) {
				    DatagramPacket packet = new DatagramPacket(sendData,
					    sendData.length, IPAddress, udpPort);
				    if(datagramSocket != null){
					datagramSocket.send(packet);
				    }
				    Thread.sleep(alive);
				}
		    } catch (SocketException e) {
	
		    } catch (UnknownHostException e) {
	
		    } catch (IOException e) {
	
		    } catch (InterruptedException e) {
	
		    } finally {
				if(datagramSocket != null){
				    datagramSocket.close();
				}
		    }
		}
    }

    public Config getConfig() {
    	return config;
    }

    public Object getResponse(Object request) {
		Object responseObject = null;
	
		try {
		    writer.writeObject(request);
		    writer.flush();
	
		    while (true) {
			responseObject = reader.readObject();
			return responseObject;
		    }
	
		} catch (IOException e) {
		    e.printStackTrace();
		} catch (ClassNotFoundException e) {
		    e.printStackTrace();
		}
	
		return responseObject;
    }

    @Command
    public MessageResponse exit() throws IOException {
	
	//	try {
	//	    socket.close();
	//	}
	//	catch (Exception e) {
	//	    
	//	}
	//	
	//	try {
	//	    datagramSocket.close();
	//	}
	//	catch (Exception e) {
	//	    
	//	}
		
		if(socket != null){
		    try {
		    	socket.close();
		    } catch (Exception exc) {
	
		    } finally {
		    	socket = null;
		    }
		}
		
		if(datagramSocket != null){
		    try {
		    	datagramSocket.close();
		    } catch (Exception exc) {
	
		    } finally {
		    	datagramSocket = null;
		    }
		}
		
		try {
		    threadExecutor.shutdownNow();
		}
		catch (Exception e) {
		    
		}
		
		shellThread.interrupt();
		shell.close();
	
		try {
		    System.in.close();
		    threadExecutor.shutdown();
		} catch (Exception exc) {
	
		}
	
		return new MessageResponse("Connection terminated!");
    }

    public static ExecutorService getThreadExecutor() {
    	return threadExecutor;
    }

    public static void setThreadExecutor(ExecutorService threadExecutor) {
    	FileServer.threadExecutor = threadExecutor;
    }

    /**
     * @param args
     */
    public static void main(String[] args) {
		try {
		    ComponentFactory componentFactory = new ComponentFactory();
		    componentFactory.startFileServer(new Config(args[0]), new Shell(args[0], System.out, System.in));
	
		} catch (Exception exc) {
		    exc.printStackTrace();
		}
    }
}
