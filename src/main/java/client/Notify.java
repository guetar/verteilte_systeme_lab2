package client;

import java.io.IOException;
import java.rmi.RemoteException;

import cli.Shell;

import rmi.INotify;

public class Notify implements INotify {
    Shell shell = null;

    public Notify() throws RemoteException {
	super();
    }

    @Override
    public void subscribeResponse(String message) throws RemoteException {
	shell = Client.getShell();
	try {
	    shell.writeLine(message);
	} catch (IOException e) {

	}
    }
}
