package proxy;

import java.util.ArrayList;
import java.util.List;

public class User {

    private String name;
    private String password;
    private long credits;
    private boolean online;
    private static List<User> userList = new ArrayList<User>();

    public User(String name, String password, long credits) {
	setName(name);
	setPassword(password);
	setCredits(credits);
	setOnline(false);
    }

    public static void addUsertoList(User u) {
	userList.add(u);
    }

    /**
     * @return the name
     */
    public String getName() {
	return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(String name) {
	this.name = name;
    }

    /**
     * @return the password
     */
    public String getPassword() {
	return password;
    }

    /**
     * @param password
     *            the password to set
     */
    public void setPassword(String password) {
	this.password = password;
    }

    /**
     * @return the credits
     */
    public long getCredits() {
	return credits;
    }

    /**
     * @param credits
     *            the credits to set
     */
    public void setCredits(long credits) {
	this.credits = credits;
    }

    /**
     * @return the userList
     */
    public static List<User> getUserList() {
	return userList;
    }

    /**
     * @param userList
     *            the userList to set
     */
    public void setUserList(ArrayList<User> userList) {
	User.userList = userList;
    }


    /**
     * @return user
     * 			with given name
     */
    public static User getUser(String name) {
    	for (User user : User.getUserList()) {
    		if(user.getName().equals(name)) {
    			return user;
    		}
    	}
    	return null;
    }

    /**
     * @return the online
     */
    public boolean isOnline() {
	return online;
    }

    /**
     * @param online
     *            the online to set
     */
    public void setOnline(boolean online) {
	this.online = online;
    }
}
