package rmi;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface INotify extends Remote {
	
	public void subscribeResponse(String message) throws RemoteException;
}