package testFileserver;

import util.ComponentFactory;
import util.Config;
import cli.Shell;

public class testFS1 {

    /**
     * @param args
     */
    public static void main(String[] args) {
	try {

	    ComponentFactory componentFactory = new ComponentFactory();

	    componentFactory.startFileServer(new Config("fs1"), new Shell(
		    "fs1", System.out, System.in));
	  
	} catch (Exception exc) {
	    exc.printStackTrace();
	}

    }

}
