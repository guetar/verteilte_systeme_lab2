package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

import util.ComponentFactory;
import util.Config;

import cli.Command;
import cli.Shell;
import message.Response;
import message.request.BuyRequest;
import message.request.CreditsRequest;
import message.request.DownloadFileRequest;
import message.request.DownloadTicketRequest;
import message.request.ListRequest;
import message.request.LoginRequest;
import message.request.LogoutRequest;
import message.request.UploadRequest;
import message.response.BuyResponse;
import message.response.CreditsResponse;
import message.response.DownloadFileResponse;
import message.response.DownloadTicketResponse;
import message.response.ListResponse;
import message.response.LoginResponse;
import message.response.MessageResponse;
import model.DownloadTicket;

public class Client implements IClientCli {
    private final Config config;
    private final Shell shell;
    private Thread shellThread = null;

    private Socket socket = null;
    private InputStream isSocket = null;
    private OutputStream osSocket = null;
    private ObjectOutputStream writer = null;
    private ObjectInputStream reader = null;

    private String dir = null;
    private String host = null;
    private int tcpPort = 0;

    public Client() throws Exception {
	this.config = new Config("client");
	this.shell = new Shell("client", System.out, System.in);
	new Client(config, shell);

    }

    public Client(final Config config, final Shell shell) throws Exception {
	this.config = config;
	this.shell = shell;

	if (config == null) {
	    throw new IllegalArgumentException();
	}

	try {
	    validateConfig(config);
	    openConnection();
	} catch (Exception exc) {
	    System.out.println(exc.getMessage());
	    closeConnection();
	}

	shell.register(this);
	shellThread = new Thread(shell);
	shellThread.start();
    }

    private void validateConfig(Config config) throws Exception {
	try {
	    dir = config.getString("download.dir");
	    host = config.getString("proxy.host");
	    tcpPort = config.getInt("proxy.tcp.port");
	} catch (Exception exc) {
	    throw new Exception("client.properties invalid");
	}
    }

    private void openConnection() throws Exception {
	try {
	    if (socket == null) {
		socket = new Socket(host, tcpPort);
		isSocket = socket.getInputStream();
		osSocket = socket.getOutputStream();
	    }
	} catch (Exception exc) {
	    throw new Exception("Couldn't get I/O for connection to the host "
		    + host);
	}

	try {
	    writer = new ObjectOutputStream(osSocket);
	    reader = new ObjectInputStream(isSocket);
	} catch (IOException exc) {
	    throw new Exception(
		    "Couldn't initialize Object Input / Output Stream to the host "
			    + host);
	}
    }

    private void closeConnection() {
	try {
	    writer.close();
	} catch (Exception exc) {
	    
	}
	try {
	    reader.close();
	} catch (Exception exc) {
	    
	}

	try {
	    isSocket.close();
	} catch (Exception exc) {
	   
	} finally {
	    isSocket = null;
	}

	try {
	    osSocket.close();
	} catch (Exception exc) {
	    
	} finally {
	    osSocket = null;
	}

	try {
	    socket.close();
	} catch (Exception exc) {
	    
	} finally {
	    socket = null;
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
	    
	} catch (ClassNotFoundException e) {
	    
	}

	return responseObject;
    }

    @Command
    public LoginResponse login(String username, String password)
	    throws IOException {
	LoginResponse response = null;

	Object responseObject = getResponse(new LoginRequest(username, password));
	
	if (responseObject instanceof LoginResponse) {
	    response = (LoginResponse) responseObject;
	} else if (responseObject instanceof MessageResponse) {
	    shell.writeLine(responseObject.toString());
	} else {
	    shell.writeLine("Invalid response");
	}
	return response;
    }

    @Command
    public Response credits() throws IOException {
	CreditsResponse response = null;
	Object responseObject = (Response) getResponse(new CreditsRequest());
	
	if (responseObject instanceof CreditsResponse) {
	    response = (CreditsResponse) responseObject;
	} else if (responseObject instanceof MessageResponse) {
	    shell.writeLine(responseObject.toString());
	}
	return response; 
    }

    @Command
    public Response buy(long credits) throws IOException {
	BuyResponse response = null;
	Object responseObject = (Response) getResponse(new BuyRequest(credits));
	
	if (responseObject instanceof BuyResponse) {
	    response = (BuyResponse) responseObject;
	} else if (responseObject instanceof MessageResponse) {
	    shell.writeLine(responseObject.toString());
	}
	return response; 
    }

    @Command
    public Response list() throws IOException {
	ListResponse response = null;
	Object responseObject = (Response) getResponse(new ListRequest());
	
	if (responseObject instanceof ListResponse) {
	    response = (ListResponse) responseObject;
	} else if (responseObject instanceof MessageResponse) {
	    shell.writeLine(responseObject.toString());
	}
	return response; 
    }

    @Command
    public Response download(String filename) throws IOException {
    	
		Object responseObject = getResponse(new DownloadTicketRequest(filename));
		DownloadTicket downloadTicket = null;
	
		if (responseObject instanceof MessageResponse) {
		    return (Response) responseObject;
		} else if (responseObject instanceof DownloadFileResponse) {
			
		    downloadTicket = ((DownloadFileResponse) responseObject).getTicket();
		    File file = new File(dir + "/" + downloadTicket.getFilename());
	    	FileOutputStream fileWriter = new FileOutputStream(file);
	
		    try {
				byte[] content = ((DownloadFileResponse) responseObject).getContent();
				fileWriter.write(content);
			    return (Response) responseObject;
	
		    } catch (IOException e) {
	
		    } finally {
		    	fileWriter.close();
		    }
		}
		return null;
    }

    @Command
    public MessageResponse upload(String filename) throws IOException {
    	
		String filePath = dir + "/" + filename;
		byte[] content = null;
		InputStream is = null;
		File file = new File(filePath);
		int version = 1;
	
		try {
		    is = new FileInputStream(filePath);
		    content = new byte[(int) file.length()];
		    is.read(content);
		    return (MessageResponse) getResponse(new UploadRequest(filename, version, content));
		    
		} catch(Exception e) {
		    return new MessageResponse("File not available.");
		} finally {
		    if(is != null){
		    	is.close();
		    }
		}
    }

    @Command
    public MessageResponse logout() throws IOException {
	return (MessageResponse) getResponse(new LogoutRequest());
    }

    @Command
    public MessageResponse exit() throws IOException {
	logout();
	closeConnection();

	shellThread.interrupt();
	shell.close();

	try {
	    System.in.close();
	} catch (Exception exc) {
	    
	}
	
	return new MessageResponse("Connection terminated!");
    }

    public static void main(String[] args) {
	try {
	    ComponentFactory componentFactory = new ComponentFactory();

	    componentFactory.startClient(new Config("client"), new Shell(
		    "client", System.out, System.in));

	} catch (Exception exc) {
	    exc.printStackTrace();
	}
    }
}
