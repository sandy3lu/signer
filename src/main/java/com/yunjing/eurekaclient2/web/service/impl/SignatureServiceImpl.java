package com.yunjing.eurekaclient2.web.service.impl;


import com.yunjing.eurekaclient2.common.base.ResultInfo;
import com.yunjing.eurekaclient2.feign.remote.KeyServiceRemote;

import com.yunjing.eurekaclient2.web.service.SignatureService;


import org.apache.http.HttpStatus;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoException;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.*;

import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.*;


/**
 * <p>
 * key管理表 服务实现类
 * </p>
 *
 * @author scyking-auto
 * @since 2019-01-28
 */
@Service
public class SignatureServiceImpl implements SignatureService {

    protected Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${user.define.crypto.useToken}")
    public String useToken;

    @Autowired
    KeyServiceRemote keyServiceRemote;

    @Override
    public boolean verify(String algorithmID, String publicKey, byte[] data, byte[] sig) throws IOException {
        switch (algorithmID){
            case SM2:
                return verifySM2(publicKey,data,sig);

            case RSA:
                return verifyRSA(publicKey,data,sig);

        }
        return false;
    }

    private boolean verifyRSA(String publicKey, byte[] data, byte[] sig) throws IOException {

        byte[] keydata = ByteUtils.fromHexString(publicKey);
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keydata);
        PublicKey pubkey = BouncyCastleProvider.getPublicKey(subjectPublicKeyInfo);
        BCRSAPublicKey rsa = (BCRSAPublicKey) pubkey;

        RSAKeyParameters rsaPublic = new RSAKeyParameters(false, rsa.getModulus(), rsa.getPublicExponent());
        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest(), NISTObjectIdentifiers.id_sha256);
        signer.init(false, rsaPublic);
        signer.update(data, 0, data.length);
        return signer.verifySignature(sig);
    }

    private boolean verifySM2(String publicKey, byte[] data, byte[] sig) throws IOException {
        if (useToken.toLowerCase().contains("false")) {

            byte[] keydata = ByteUtils.fromHexString(publicKey);
            SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keydata);
            PublicKey pubkey = BouncyCastleProvider.getPublicKey(subjectPublicKeyInfo);
            BCECPublicKey localECPublicKey = (BCECPublicKey)pubkey;
            ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                    localECParameterSpec.getG(), localECParameterSpec.getN());
            ECPublicKeyParameters param = new ECPublicKeyParameters(localECPublicKey.getQ(),localECDomainParameters);

            SM2Signer signer = new SM2Signer();
            signer.init(false, param);
            signer.update(data, 0, data.length);
            boolean result = signer.verifySignature(sig);
            return result;
        }else{
            //TODO: token
            return false;
        }
    }
    @Override
    public byte[] sign(String userID, int keyID, byte[] data) throws IOException, CryptoException {
        // get private and public key from kmc
        ResultInfo rs = keyServiceRemote.getKey(userID,keyID);

        int code = (int)rs.get("code");
        if(code == HttpStatus.SC_OK){
            String publicKey = (String)rs.get("publicKey");
            String privateKey = (String)rs.get("privateKey");
            String type = (String)rs.get("keyType");
            if(type.toLowerCase().contains("sm2")){
                //SM2
                return sign(SM2,privateKey,publicKey,data);
            }else{
                //RSA
                return sign(RSA,privateKey,publicKey,data);
            }

        }else{
            throw new RuntimeException((String)rs.get("msg"));
        }
    }

    @Override
    public byte[] sign(String algorithmID, String privateKey, String publicKey, byte[] data) throws IOException, CryptoException {
        switch (algorithmID){
            case SM2:
                return signSM2(privateKey,publicKey,data);

            case RSA:
                return signRSA(privateKey,data);
        }
        return new byte[0];
    }

    private byte[] signRSA(String privateKey, byte[] data) throws IOException, CryptoException {
        byte[] keydata = ByteUtils.fromHexString(privateKey);
        org.bouncycastle.asn1.pkcs.PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(keydata);
        BCRSAPrivateCrtKey rsa= (BCRSAPrivateCrtKey)BouncyCastleProvider.getPrivateKey(privateKeyInfo);

        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        RSAPrivateCrtKeyParameters rsaPrivate = new RSAPrivateCrtKeyParameters(rsa.getModulus(), rsa.getPublicExponent(), rsa.getPrivateExponent(),
                rsa.getPrimeP(), rsa.getPrimeQ(), rsa.getPrimeExponentP(), rsa.getPrimeExponentQ(), rsa.getCrtCoefficient());

        signer.init(true, rsaPrivate);
        signer.update(data, 0, data.length);
        byte[] sig = signer.generateSignature();
        return sig;
    }

    private byte[] signSM2(String privateKey, String publicKey, byte[] data) throws IOException, CryptoException {

        if (useToken.toLowerCase().contains("false")){

            byte[] keydata = ByteUtils.fromHexString(privateKey);
            org.bouncycastle.asn1.pkcs.PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(keydata);
            BCECPrivateKey priKey= (BCECPrivateKey)BouncyCastleProvider.getPrivateKey(privateKeyInfo);
            ECParameterSpec localECParameterSpec = priKey.getParameters();
            ECDomainParameters localECDomainParameters = new ECDomainParameters(localECParameterSpec.getCurve(),
                    localECParameterSpec.getG(), localECParameterSpec.getN());
            ECPrivateKeyParameters ecKeyParameters = new ECPrivateKeyParameters(priKey.getD(),localECDomainParameters);
            SM2Signer signer = new SM2Signer();
            signer.init(true, ecKeyParameters);
            signer.update(data, 0, data.length);
            return signer.generateSignature();

        }else{
            // TODO: token
            return new byte[0];
        }
    }
}
