package com.nobiz.tls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

//@Slf4j
public class HttpsUtil {

    private static final Logger log = LoggerFactory.getLogger(HttpsUtil.class);
    //CA根证书文件路径
    private String caPath="D:/workspace/java/nobiz/authentication/src/main/resources/tls/ca.jks";
    //CA根证书生成密码
    private String caPassword="123456";
    //客户端证书文件名
    private String clientCertPath="D:/workspace/java/nobiz/authentication/src/main/resources/tls/cert.jks";
    //客户端证书生成密码
    private String clientCertPassword="123456";

    private SSLSocketFactory sslFactory;

    public static void main(String[] args) {
        HttpsUtil httpsUtil = new HttpsUtil();
        String requestBody ="{\"username\":\"admin\",\"password\":\"123456\"}";
        try {
            Map<String, Object> stringObjectMap = httpsUtil.httpsPost("https://192.168.0.143:443/api/auth/logon", requestBody);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //https POST请求返回结果和结果码
    public Map<String,Object> httpsPost(String requestUrl, String xml) throws Exception {
        Map<String,Object> map=new HashMap<>();
        OutputStreamWriter wr=null;
        HttpURLConnection conn=null;
        try {
            URL url = new URL(requestUrl);
            //start 这一段代码必须加在open之前，即支持ip访问的关键代码
            HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String s, SSLSession sslSession) {
                    return true;
                }
            });
            //end
            byte[] xmlBytes = xml.getBytes();
            conn = (HttpsURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestMethod("POST");
            //根据自己项目需求设置Content-Type
            conn.setRequestProperty("Content-Type", "application/xml;charset=UTF-8");
            conn.setRequestProperty("Content-Length", String.valueOf(xmlBytes.length));
            ((HttpsURLConnection) conn).setSSLSocketFactory(getSslFactory());
            wr = new OutputStreamWriter(conn.getOutputStream());
            wr.write(xml);
            wr.close();
            conn.connect();
            String responseBody = getResponseBodyAsString(conn);
            int responseCode=getResponseCode(conn);
            map.put("responseBody",responseBody);
            map.put("responseCode",responseCode);
            if (getResponseCode(conn) == 200) {
                System.out.println("请求成功");
            } else {
                System.out.println("请求失败");
            }
            System.out.println(responseBody);
            conn.disconnect();
        } catch (Exception e) {
            log.error("HTTPS请求出现异常，请求参数为："+xml);
            e.printStackTrace();
            throw e;
        }finally {
            try{
                if(wr!=null){
                    wr.close();
                }
                if(conn!=null){
                    conn.disconnect();
                }
            }catch (Exception e){

            }
        }
        return map;
    }

    public SSLSocketFactory getSslFactory() throws Exception {
        if (sslFactory == null) {
            SSLContext sslContext = SSLContext.getInstance("SSL");
            TrustManager[] tm = {new MyX509TrustManager()};
            KeyStore trustStore = KeyStore.getInstance("JKS");
            //加载客户端证书
            FileInputStream clientInputStream=new FileInputStream(clientCertPath);
            trustStore.load(clientInputStream, clientCertPassword.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(trustStore, clientCertPassword.toCharArray());
            sslContext.init(kmf.getKeyManagers(), tm, new SecureRandom());
            sslFactory = sslContext.getSocketFactory();
        }
        return sslFactory;
    }

    public int getResponseCode(HttpURLConnection connection) throws Exception {
        return connection.getResponseCode();
    }

    public String getResponseBodyAsString(HttpURLConnection connection) throws Exception {
        BufferedReader reader = null;
        if (connection.getResponseCode() == 200) {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
        }
        StringBuffer buffer = new StringBuffer();
        String line = null;
        while ((line = reader.readLine()) != null) {
            buffer.append(line);
        }
        reader.close();
        return buffer.toString();
    }

    class MyX509TrustManager implements X509TrustManager {
        private X509TrustManager sunJSSEX509TrustManager;

        MyX509TrustManager() throws Exception {
            KeyStore ks = KeyStore.getInstance("JKS");
            //获取CA证书
            FileInputStream caInputStream=new FileInputStream(caPath);
            ks.load(caInputStream, caPassword.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
            tmf.init(ks);
            TrustManager tms[] = tmf.getTrustManagers();
            for (int i = 0; i < tms.length; i++) {
                if (tms[i] instanceof X509TrustManager) {
                    sunJSSEX509TrustManager = (X509TrustManager) tms[i];
                    return;
                }
            }
            throw new Exception("Couldn't not initialize");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            try {
                sunJSSEX509TrustManager.checkClientTrusted(x509Certificates, s);
            } catch (Exception e) {

            }
        }

        @Override
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            try {
                sunJSSEX509TrustManager.checkServerTrusted(x509Certificates, s);
            } catch (Exception e) {

            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return sunJSSEX509TrustManager.getAcceptedIssuers();
        }

    }
}

