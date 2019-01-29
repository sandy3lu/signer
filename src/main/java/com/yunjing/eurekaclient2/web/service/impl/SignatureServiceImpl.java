package com.yunjing.eurekaclient2.web.service.impl;


import com.yunjing.eurekaclient2.common.base.ResultInfo;
import com.yunjing.eurekaclient2.feign.remote.Client1Remote;
import com.yunjing.eurekaclient2.web.entity.Key;
import com.yunjing.eurekaclient2.web.mapper.KeyMapper;
import com.yunjing.eurekaclient2.web.service.SignatureService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoException;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
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
public class SignatureServiceImpl extends ServiceImpl<KeyMapper, Key> implements SignatureService {

    protected Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${user.define.crypto.useToken}")
    public String useToken;

    @Autowired
    Client1Remote client1Remote;

    @Override
    public boolean verify(String algorithmID, String publicKey, byte[] data, byte[] sig) throws IOException {
        switch (algorithmID){
            case SM2:
                return verifySM2(publicKey,data,sig);

            case RSA:
                break;
        }
        return false;
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
        ResultInfo rs = client1Remote.getKey(userID,keyID);
        String code = (String)rs.get("code");
        if(code.equals("200")){
            String publicKey = (String)rs.get("publicKey");
            String privateKey = (String)rs.get("privateKey");
            if(publicKey.length()<2048){
                //SM2
                return sign(SM2,privateKey,publicKey,data);
            }else{
                //RSA
                return new byte[0];
            }

        }else{
            throw new RuntimeException((String)rs.get("msg"));
        }
    }

    @Override
    public byte[] sign(String algorithmID, String keyContent, String publicKey, byte[] data) throws IOException, CryptoException {
        switch (algorithmID){
            case SM2:
                return signSM2(keyContent,publicKey,data);

            case RSA:
                break;
        }
        return new byte[0];
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
