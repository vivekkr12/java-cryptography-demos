package com.here.had.webapps.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;

public class ProvidersTest {

    @Test
    public void listAvailableProviders() {
        Provider[] providers = Security.getProviders();
        for(Provider p : providers) {
            System.out.println(p.getName());
        }
    }

    @Test
    public void addCustomProviderAndList() {
        Security.addProvider(new BouncyCastleProvider());
        Provider[] providers = Security.getProviders();
        for(Provider p : providers) {
            System.out.println(p.getName());
        }
    }
}
