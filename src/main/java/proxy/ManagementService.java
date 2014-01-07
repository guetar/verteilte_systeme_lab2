package proxy;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.rmi.RemoteException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SortedMap;
import java.util.TreeMap;

import rmi.IManagementService;
import util.Config;

public class ManagementService implements IManagementService, Serializable {
    private static final long serialVersionUID = -4735178471135418946L;
    private String filename = null;
    private int numberOfDownlaods = 0;
    private SortedMap<String, Integer> map = new TreeMap<String, Integer>();
    
    public ManagementService() throws RemoteException {
    	super();
    }
    
    @Override
	public String readQuorum() throws RemoteException {
    	String response = "Read-Quorum is set to " + Proxy.getNr()+".";
		return response;
	}
    
    @Override
	public String writeQuorum() throws RemoteException {
    	String response = "Write-Quorum is set to " + Proxy.getNw() + ".";
		return response;
	}
    
    @Override
    public String topThreeDownloads() throws RemoteException {
	String response = "";
	map = Proxy.getDownloadList();
	int i = 0;

	if (!map.isEmpty()) {
		response = "Top Three Downloads" + "\n";		
	    for (String key : map.keySet()){
		if(i++ < 3){
		    response = response + i + ". "+ key + ": " + map.get(key) + "\n";
		}
	    }
	}
	else{
	    response = "Nothing downloaded yet.";
	}

	return response;
    }
    
    @Override
    public String subscribe(String filename, int numberOfDownloads,
	    String username) throws RemoteException {
	String response = "";
	setFilename(filename);
	setNumberOfDownlaods(numberOfDownloads);
	map = Proxy.getDownloadList();
	
	if(!map.isEmpty()){
	    if(map.containsKey(filename)){
		if(map.get(filename) >= numberOfDownloads){
		   response = "Notification: " + filename + " got downloaded " + map.get(filename) + " times!";
		}
		else{
		    Subscription.addSubscriptiontoList(new Subscription(filename,
				numberOfDownloads, username));
		}
	    }
	}
	else{
	    Subscription.addSubscriptiontoList(new Subscription(filename,
			numberOfDownloads, username));
	}
	
	return response;
    }
    
    @Override
    public byte[] getProxyPublicKey() throws RemoteException {
	String pathToKeys = null;
	byte[] encKey = null;

	try {
	    Config mc = new Config("mc");
	    pathToKeys = mc.getString("keys.dir");
	} catch (Exception exc) {
	    System.out.println("mc.properties invalid");
	}

	// read in the encoded public key bytes
	FileInputStream keyfis;
	try {
	    keyfis = new FileInputStream(pathToKeys + "/proxy.pub.pem");
	    encKey = new byte[keyfis.available()];
	    keyfis.read(encKey);
	} catch (FileNotFoundException e) {

	} catch (IOException e) {

	}

	return encKey;
    }

    @Override
    public String setUserPublicKey(String username, byte[] encKey)
	    throws RemoteException {
	String date = new SimpleDateFormat("dd-MM-yyyy").format(new Date());
	String response = "Successfully transmitted public key of user: "
		+ username;
	String pathToKeys = null;

	try {
	    Config mc = new Config("mc");
	    pathToKeys = mc.getString("keys.dir");
	} catch (Exception exc) {
	    System.out.println("mc.properties invalid");
	}
	
	/* save the public key in a file */
	FileOutputStream keyfos;
	try {
	    keyfos = new FileOutputStream(pathToKeys + "/" + date + "_"+ username + ".pub.pem");
	    keyfos.write(encKey);
	    keyfos.close();

	} catch (FileNotFoundException e) {
	    response = "Error transmitting public key of user: " + username;
	} catch (IOException e) {
	    response = "Error transmitting public key of user: " + username;
	}

	return response;
    }

	public String getFilename() {
		return filename;
	}

	public void setFilename(String filename) {
		this.filename = filename;
	}

	public int getNumberOfDownlaods() {
		return numberOfDownlaods;
	}

	public void setNumberOfDownlaods(int numberOfDownlaods) {
		this.numberOfDownlaods = numberOfDownlaods;
	}
}
