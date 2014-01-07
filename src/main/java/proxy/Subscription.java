package proxy;

import java.util.ArrayList;
import java.util.List;

public class Subscription {
    private String filename;
    private int number;
    private String username;
    private static List<Subscription> subscriptionList = new ArrayList<Subscription>();
    
    public static List<Subscription> getSubscriptionList() {
        return subscriptionList;
    }

    Subscription(String filename, int number, String username){
	this.setFilename(filename);
	this.setNumber(number);
	this.setUsername(username);
    }
    
    public static void addSubscriptiontoList(Subscription s){
	subscriptionList.add(s);
    }

    /**
     * @return the filename
     */
    public String getFilename() {
	return filename;
    }

    /**
     * @param filename the filename to set
     */
    public void setFilename(String filename) {
	this.filename = filename;
    }

    /**
     * @return the number
     */
    public int getNumber() {
	return number;
    }

    /**
     * @param number the number to set
     */
    public void setNumber(int number) {
	this.number = number;
    }

    /**
     * @return the username
     */
    public String getUsername() {
	return username;
    }

    /**
     * @param username the username to set
     */
    public void setUsername(String username) {
	this.username = username;
    }

      
}
