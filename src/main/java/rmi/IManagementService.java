package rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IManagementService extends Remote{
    public String readQuorum() throws RemoteException;
    public String writeQuorum() throws RemoteException;
    public String topThreeDownloads() throws RemoteException;
    public String subscribe(String filename, int numberOfDownloads, String username) throws RemoteException;
    public byte[] getProxyPublicKey() throws RemoteException;
    public String setUserPublicKey(String username, byte[] encKey) throws RemoteException;    
}