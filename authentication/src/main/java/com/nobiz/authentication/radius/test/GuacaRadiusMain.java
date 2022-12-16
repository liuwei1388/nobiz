package com.nobiz.authentication.radius.test;

import com.nobiz.authentication.radius.model.RadiusAuthenticationProtocol;
import com.nobiz.authentication.radius.model.RadiusServiceConf;
import com.nobiz.authentication.radius.service.RadiusConnectionService;
import net.jradius.packet.RadiusPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class GuacaRadiusMain {

    private static final Logger logger = LoggerFactory.getLogger(GuacaRadiusMain.class);

    public static void main(String[] args) {
        RadiusServiceConf conf = new RadiusServiceConf();
        conf.setServer("192.168.0.143");
        conf.setAuthPort(1812);
        conf.setSharedSecret("testing123");
        RadiusAuthenticationProtocol protocol = RadiusAuthenticationProtocol.CHAP;
        conf.setAuthProtocol(protocol);
        conf.setMaxRetries(3);
        try {
            conf.setNasIp(InetAddress.getByName("192.168.0.34"));
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        conf.setTimeout(10);

        RadiusConnectionService service = new RadiusConnectionService(conf);
        try {
            RadiusPacket authenticate = service.authenticate("testing", "password", "192.168.0.34", null);
            System.out.println(authenticate);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
