package util;

import cli.Shell;
import client.Client;
import client.IClientCli;
import proxy.IProxyCli;
import proxy.Proxy;
import server.FileServer;
import server.IFileServerCli;

/**
 * Provides methods for starting an arbitrary amount of various components.
 */
public class ComponentFactory {

    /**
     * Creates and starts a new client instance using the provided
     * {@link Config} and {@link Shell}.
     * 
     * @param config
     *            the configuration containing parameters such as connection
     *            info
     * @param shell
     *            the {@code Shell} used for processing commands
     * @return the created component after starting it successfully
     * @throws Exception
     *             if an exception occurs
     */
    public IClientCli startClient(Config config, Shell shell) throws Exception {
	if (config == null) {
	    throw new IllegalArgumentException();
	}

	if (shell == null) {
	    throw new IllegalArgumentException();
	}

	IClientCli client = new Client(config, shell);

	return client;
    }

    /**
     * Creates and starts a new proxy instance using the provided {@link Config}
     * and {@link Shell}.
     * 
     * @param config
     *            the configuration containing parameters such as connection
     *            info
     * @param shell
     *            the {@code Shell} used for processing commands
     * @return the created component after starting it successfully
     * @throws Exception
     *             if an exception occurs
     */
    public IProxyCli startProxy(Config config, Shell shell) throws Exception {
	if (config == null) {
	    throw new IllegalArgumentException();
	}

	if (shell == null) {
	    throw new IllegalArgumentException();
	}

	IProxyCli proxy = new Proxy(config, shell);

	return proxy;
    }

    /**
     * Creates and starts a new file server instance using the provided
     * {@link Config} and {@link Shell}.
     * 
     * @param config
     *            the configuration containing parameters such as connection
     *            info
     * @param shell
     *            the {@code Shell} used for processing commands
     * @return the created component after starting it successfully
     * @throws Exception
     *             if an exception occurs
     */
    public IFileServerCli startFileServer(Config config, Shell shell)
	    throws Exception {
	if (config == null) {
	    throw new IllegalArgumentException();
	}

	if (shell == null) {
	    throw new IllegalArgumentException();
	}

	IFileServerCli fileserver= new FileServer(config, shell);

	return fileserver;
    }
 
}
