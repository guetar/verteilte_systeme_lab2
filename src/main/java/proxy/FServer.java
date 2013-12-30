package proxy;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

public class FServer implements Comparable<FServer> {

    private String ip = "test";
    private int tcpPort;
    private boolean online;
    private InetAddress address;
    private String dir;
    private long usage = 500;
    private long lastTime = 0;
    private static ArrayList<FServer> fileServerList = new ArrayList<FServer>();
    private Set<String> listFiles = new HashSet<String>();
    
    public FServer(int tcpPort) {
	setOnline(true);
	setLastTime(System.currentTimeMillis());
    }
    
    public FServer(String dir, int tcpPort, InetAddress address) {
	setDir(dir);
	setTcpPort(tcpPort);
	setAddress(address);
	setOnline(true);
	setLastTime(System.currentTimeMillis());
	setUsage(500);
    }
    
    public Set<String> getListFiles() {
        return listFiles;
    }

    public void setListFiles(Set<String> listFiles) {
        this.listFiles = listFiles;
    }

    public static ArrayList<FServer> getFileServerList() {
        return fileServerList;
    }

    public static void addFileServertoList(FServer fServer) {
	fileServerList.add(fServer);
    }

    /**
     * @return the ip
     */
    public String getIp() {
	return ip;
    }

    /**
     * @param ip
     *            the ip to set
     */
    public void setIp(String ip) {
	this.ip = ip;
    }
    
    /**
     * @return the tcpPort
     */
    public int getTcpPort() {
	return tcpPort;
    }

    /**
     * @param tcpPort
     *            the tcpPort to set
     */
    public void setTcpPort(int tcpPort) {
	this.tcpPort = tcpPort;
    }
    
    /**
     * @return the dir
     */
    public String getDir() {
	return dir;
    }

    /**
     * @param dir
     *            the dir to set
     */
    public void setDir(String dir) {
	this.dir = dir;
    }
    
    /**
     * @return the usage
     */
    public long getUsage() {
	return usage;
    }

    /**
     * @param usage
     *            the usage to set
     */
    public void setUsage(long usage) {
	this.usage = usage;
    }

    /**
     * @return the lastTime
     */
    public long getLastTime() {
	return lastTime;
    }

    /**
     * @param lastTime
     *            the lastTime to set
     */
    public void setLastTime(long lastTime) {
	this.lastTime = lastTime;
    }

    /**
     * @return the online
     */
    public boolean isOnline() {
	return online;
    }

    /**
     * @param online the online to set
     */
    public void setOnline(boolean online) {
	this.online = online;
    }

    /**
     * @return the address
     */
    public InetAddress getAddress() {
	return address;
    }

    /**
     * @param address the address to set
     */
    public void setAddress(InetAddress address) {
	this.address = address;
    }

    @Override
    public int compareTo(FServer fs) {
        if (this.getUsage() < fs.getUsage()) {
            return -1;
        } else if (this.getUsage() > fs.getUsage()) {
            return 1;
        } else {
            return 0;
        }
    }
}
