package com.graviteesource.policy.threatprotection.xml;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class XmlException extends Exception {

    private String key;

    public XmlException(String key, String message) {
        super(message);
        this.key = key;
    }

    public XmlException(String key, String message, Exception e) {
        super(message, e);
        this.key = key;
    }

    public String getKey() {
        return key;
    }
}
