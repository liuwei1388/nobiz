package com.nobiz.common.utils;

public class Main {

    public static void main(String[] args) {

        String publicKey = RsaUtils.getPublicKey();
        System.out.println("publicKey: " + publicKey);

    }
}
