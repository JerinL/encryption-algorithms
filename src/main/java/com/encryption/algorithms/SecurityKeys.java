package com.encryption.algorithms;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.security.PrivateKey;

@Getter
@Setter
@ToString
public class SecurityKeys {

    public String uniqueId;
    public String publicKey;
    public String privateKey;
    public String encryptedData;
    private PrivateKey privateKey1;

}
