package proxy;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.rmi.RemoteException;
import java.text.SimpleDateFormat;
import java.util.Date;

import rmi.IManagementService;
import util.Config;

public class ManagementService implements IManagementService, Serializable {
    private static final long serialVersionUID = -4735178471135418946L;
    
    public ManagementService() throws RemoteException {
    	super();
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
}
