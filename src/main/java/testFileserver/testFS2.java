package testFileserver;

import util.ComponentFactory;
import util.Config;
import cli.Shell;

public class testFS2 {

    public static void main(String[] args) {
 	try {

 	    ComponentFactory componentFactory = new ComponentFactory();

 	    componentFactory.startFileServer(new Config("fs2"), new Shell(
 		    "fs2", System.out, System.in));
 	  
 	} catch (Exception exc) {
 	    exc.printStackTrace();
 	}

     }
}
