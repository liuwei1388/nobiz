package com.nobiz.authentication.radius.service;

import com.nobiz.authentication.radius.model.RadiusServiceConf;
import net.jradius.client.RadiusClient;
import net.jradius.client.auth.EAPTLSAuthenticator;
import net.jradius.client.auth.EAPTTLSAuthenticator;
import net.jradius.client.auth.PAPAuthenticator;
import net.jradius.client.auth.RadiusAuthenticator;
import net.jradius.dictionary.Attr_CleartextPassword;
import net.jradius.dictionary.Attr_ClientIPAddress;
import net.jradius.dictionary.Attr_NASIPAddress;
import net.jradius.dictionary.Attr_NASPortType;
import net.jradius.dictionary.Attr_ReplyMessage;
import net.jradius.dictionary.Attr_RewriteRule;
import net.jradius.dictionary.Attr_State;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;
import net.jradius.exception.RadiusException;
import net.jradius.packet.AccessChallenge;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusPacket;
import net.jradius.packet.RadiusResponse;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;

public class RadiusConnectionService {

    private final Logger logger = LoggerFactory.getLogger(RadiusConnectionService.class);

    private final RadiusServiceConf radiusServiceConf;

    public RadiusConnectionService(RadiusServiceConf conf) {
        this.radiusServiceConf = conf;
    }

    private RadiusClient createRadiusConnection() throws Exception {
        try {
            return new RadiusClient(InetAddress.getByName(radiusServiceConf.getServer()),
                    radiusServiceConf.getSharedSecret(),
                    radiusServiceConf.getAuthPort(),
                    1813,
                    radiusServiceConf.getTimeout());
        } catch (UnknownHostException e) {
            logger.debug("Failed to resolve host.", e);
            throw new Exception("Failed to resolve RADIUS server host.", e);
        } catch (IOException e) {
            logger.debug("Failed to communicate with host.", e);
            throw new Exception("Failed to communicate with RADIUS server.", e);
        }
    }

    private RadiusAuthenticator getRadiusAuthenticator() throws Exception {
        RadiusAuthenticator radiusAuthenticator = radiusServiceConf.getAuthProtocol().getAuthenticator();

        if (radiusAuthenticator instanceof EAPTLSAuthenticator) {
            EAPTLSAuthenticator tlsAuth = (EAPTLSAuthenticator) radiusAuthenticator;
            File caFile = radiusServiceConf.getCaFile();
            if (caFile != null) {
                tlsAuth.setCaFile(caFile.toString());
                tlsAuth.setCaFileType(radiusServiceConf.getCaType());
                String caPassword = radiusServiceConf.getCaPassword();
                if (caPassword != null) {
                    tlsAuth.setCaPassword(caPassword);
                }
            }
            String keyPassword = radiusServiceConf.getKeyPassword();
            if (keyPassword != null) {
                tlsAuth.setKeyPassword(keyPassword);
            }

            File keyFile = radiusServiceConf.getKeyFile();
            tlsAuth.setKeyFile(keyFile.toString());
            tlsAuth.setKeyFileType(radiusServiceConf.getKeyType());
            tlsAuth.setTrustAll(radiusServiceConf.getTrustAll());
        }
        if (radiusAuthenticator instanceof PAPAuthenticator) {

        }

        return radiusAuthenticator;
    }

    public RadiusPacket authenticate(String username, String secret, String clientAddress, byte[] state) throws Exception {
        if (username == null || username.isEmpty()) {
            logger.warn("Anonymous access not allowed with RADIUS client.");
            return null;
        }

        if (secret == null || secret.isEmpty()) {
            logger.warn("Password/secret required for RADIUS authentication.");
            return null;
        }

        RadiusClient radiusClient = createRadiusConnection();
        AttributeFactory.loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");

        RadiusAuthenticator radAuth = getRadiusAuthenticator();

        try {
            AttributeList radAttrs = new AttributeList();
            radAttrs.add(new Attr_UserName(username));
            radAttrs.add(new Attr_ClientIPAddress(InetAddress.getByName(clientAddress)));
            radAttrs.add(new Attr_NASIPAddress(radiusServiceConf.getNasIp()));
            radAttrs.add(new Attr_NASPortType(Attr_NASPortType.Virtual));
            if (state != null && state.length > 0) {
                radAttrs.add(new Attr_State(state));
            }
            radAttrs.add(new Attr_UserPassword(secret));
            radAttrs.add(new Attr_CleartextPassword(secret));

            AccessRequest radAcc = new AccessRequest(radiusClient);

            // EAP-TTLS tunnels protected attributes inside the TLS layer
            if (radAuth instanceof EAPTTLSAuthenticator) {
                radAuth.setUsername(new Attr_UserName(username));
                ((EAPTTLSAuthenticator) radAuth).setTunneledAttributes(radAttrs);
            } else {
                radAcc.addAttributes(radAttrs);
            }

            radAuth.setupRequest(radiusClient, radAcc);
            radAuth.processRequest(radAcc);
            RadiusResponse reply = radiusClient.authenticate(radAcc, radAuth, radiusServiceConf.getMaxRetries());

            while ((reply instanceof AccessChallenge) && (reply.findAttribute(Attr_ReplyMessage.TYPE) == null)) {
                radAuth.processChallenge(radAcc, reply);
                reply = radiusClient.sendReceive(radAcc, radiusServiceConf.getMaxRetries());
            }

            return reply;
        } catch (RadiusException e) {
            logger.error("Unable to complete authentication.", e);
            logger.debug("Authentication with RADIUS failed.", e);
            return null;
        } catch (NoSuchAlgorithmException e) {
            logger.error("No such RADIUS algorithm: {}", e.getMessage());
            logger.debug("Unknown RADIUS algorithm", e);
            return null;
        } catch (UnknownHostException e) {
            logger.error("Could not resolve address: {}", e.getMessage());
            logger.debug("Exception resolving host address.", e);
            return null;
        } finally {
            radiusClient.close();
        }
    }

    public RadiusPacket sendChallengeResponse(String username, String response,
                                              String clientAddress, byte[] state) throws Exception {

        if (username == null || username.isEmpty()) {
            logger.error("Challenge/response to RADIUS requires a username.");
            return null;
        }

        if (state == null || state.length == 0) {
            logger.error("Challenge/response to RADIUS requires a prior state.");
            return null;
        }

        if (response == null || response.isEmpty()) {
            logger.error("Challenge/response to RADIUS requires a response.");
            return null;
        }

        return authenticate(username, response, clientAddress, state);

    }
}
