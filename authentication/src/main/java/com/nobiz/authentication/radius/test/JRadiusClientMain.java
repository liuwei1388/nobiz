package com.nobiz.authentication.radius.test;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.EAPMD5Authenticator;
import net.jradius.dictionary.Attr_NASPort;
import net.jradius.dictionary.Attr_NASPortType;
import net.jradius.dictionary.Attr_ReplyMessage;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusResponse;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;

public class JRadiusClientMain {

    private static final Logger logger = LoggerFactory.getLogger(JRadiusClientMain.class);

    public static void main(String[] args) {

        String serverIp = "192.168.0.143";
        String username = "testing";
        String password = "password";
        String secret = "testing123";
        logger.info("Start to test Linux FreeRadius.");
        testRadius(serverIp, username, password, secret);

//        serverIp = "192.168.0.34";
//        username = "test";
//        password = "password";
//        secret = "WinRadius";
//        logger.info("Start to test WinRadius.");
//        testRadius(serverIp, username, password, secret);
    }

    private static void testRadius(String serverIp, String username, String password, String secret) {

        try {
            AttributeFactory.loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");
            InetAddress host = InetAddress.getByName(serverIp);
            RadiusClient rc = new RadiusClient(host, secret, 1812, 1813, 20);
            AttributeList attrs = new AttributeList();
            attrs.add(new Attr_UserName(username));
            attrs.add(new Attr_NASPortType(Attr_NASPortType.Wireless80211));
            attrs.add(new Attr_NASPort(1));
            AccessRequest request = new AccessRequest(rc, attrs);
            request.addAttribute(new Attr_UserPassword(password));
            RadiusResponse reply = rc.authenticate(request, new EAPMD5Authenticator() {
            }, 5);

            logger.info("Received:\n" + reply.toString());

            boolean isAuthenticated = (reply instanceof AccessAccept);

            String replyMessage = (String) reply.getAttributeValue(Attr_ReplyMessage.TYPE);
            if (replyMessage != null) {
                logger.info("Reply Message: " + replyMessage);
            }
            System.out.println(isAuthenticated);
        } catch (Exception e) {
            logger.error("Failed", e);
        }
    }

}
