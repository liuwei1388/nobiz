package com.nobiz.authentication.radius.test;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tinyradius.util.RadiusClient;
import org.tinyradius.util.RadiusException;
import org.tinyradius.util.RadiusServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

public class TinyRadiusMain {

    private static final Logger logger = LoggerFactory.getLogger(TinyRadiusMain.class);

    public static void main(String[] args) {

        RadiusServer server = new RadiusServer() {
            @Override
            public String getSharedSecret(InetSocketAddress client) {
                return "testing123";
            }

            @Override
            public String getUserPassword(String userName) {
                return "password";
            }
        };
        try {
            server.setListenAddress(InetAddress.getByName("192.168.0.34"));
            server.setAuthPort(1812);
            server.setAcctPort(1813);

            server.start(true, true);
            RadiusClient client = new RadiusClient("192.168.0.143", "testing123");
            client.setAuthPort(1812);
            client.setAcctPort(1813);
            boolean authenticate = client.authenticate("testing1", "password");
            System.out.println(authenticate);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (RadiusException e) {
            e.printStackTrace();
        }
    }
}
