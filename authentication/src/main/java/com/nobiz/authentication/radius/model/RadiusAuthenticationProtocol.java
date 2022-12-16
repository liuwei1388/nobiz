package com.nobiz.authentication.radius.model;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.RadiusAuthenticator;

public enum RadiusAuthenticationProtocol {

    PAP("pap"),
    CHAP("chap"),
    ;

    private final String JRADIUS_PROTOCOL_NAME;

    RadiusAuthenticationProtocol(String protocol) {
        this.JRADIUS_PROTOCOL_NAME = protocol;
    }

    public RadiusAuthenticator getAuthenticator() {
        RadiusAuthenticator authenticator = RadiusClient.getAuthProtocol(JRADIUS_PROTOCOL_NAME);
        if (authenticator == null) {
            throw new IllegalStateException(String.format("JRadius failed "
                    + "to locate its own support for protocol \"%s\". This is "
                    + "likely a bug in the JRadius Library.", JRADIUS_PROTOCOL_NAME));
        }
        return authenticator;
    }
}
