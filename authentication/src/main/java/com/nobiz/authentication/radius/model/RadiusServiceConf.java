package com.nobiz.authentication.radius.model;

import java.io.File;
import java.net.InetAddress;

public class RadiusServiceConf {

    /** default: localhost。 */
    private String server;
    /** 授权端口。  default: 1812。*/
    private Integer authPort;
    /** 计费端口。 default: 1813。*/
    private Integer acctPort;
    /** defaultName: radius-shared-secret。 */
    private String sharedSecret;
    /** defaultName: radius-auth-protocol。 */
    private RadiusAuthenticationProtocol authProtocol;

    /** default: 5。 defaultName: radius-max-retries。 */
    private Integer maxRetries;
    /** default: 60。 defaultName: radius-timeout。 */
    private Integer timeout;

    /** default: ca.crt。 defaultName: radius-ca-file。 */
    private File caFile;
    /** default: radius.key。 defaultName: radius-key-file。 */
    private File keyFile;
    /** defaultName: radius-ca-password。 */
    private String caPassword;
    /** default: pem。 defaultName: radius-ca-type。 */
    private String caType;
    /** default: pem。 defaultName: radius-key-password。 */
    private String keyPassword;
    /** default: pem。 defaultName: radius-key-type。 */
    private String keyType;

    /** default: false。 defaultName: radius-trust-all。 */
    private Boolean trustAll;

    /** default: localhost。 defaultName: radius-nas-ip。 */
    private InetAddress nasIp;

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public Integer getAuthPort() {
        return authPort;
    }

    public void setAuthPort(Integer authPort) {
        this.authPort = authPort;
    }

    public Integer getAcctPort() {
        return acctPort;
    }

    public void setAcctPort(Integer acctPort) {
        this.acctPort = acctPort;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public RadiusAuthenticationProtocol getAuthProtocol() {
        return authProtocol;
    }

    public void setAuthProtocol(RadiusAuthenticationProtocol authProtocol) {
        this.authProtocol = authProtocol;
    }

    public Integer getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(Integer maxRetries) {
        this.maxRetries = maxRetries;
    }

    public Integer getTimeout() {
        return timeout;
    }

    public void setTimeout(Integer timeout) {
        this.timeout = timeout;
    }

    public File getCaFile() {
        return caFile;
    }

    public void setCaFile(File caFile) {
        this.caFile = caFile;
    }

    public File getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(File keyFile) {
        this.keyFile = keyFile;
    }

    public String getCaPassword() {
        return caPassword;
    }

    public void setCaPassword(String caPassword) {
        this.caPassword = caPassword;
    }

    public String getCaType() {
        return caType;
    }

    public void setCaType(String caType) {
        this.caType = caType;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public Boolean getTrustAll() {
        return trustAll;
    }

    public void setTrustAll(Boolean trustAll) {
        this.trustAll = trustAll;
    }

    public InetAddress getNasIp() {
        return nasIp;
    }

    public void setNasIp(InetAddress nasIp) {
        this.nasIp = nasIp;
    }
}
