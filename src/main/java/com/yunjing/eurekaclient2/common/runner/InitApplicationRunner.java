package com.yunjing.eurekaclient2.common.runner;

import com.yunjing.eurekaclient2.web.entity.DictConstant;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

/**
 * @ClassName InitApplicationRunner
 * @Description 系统启动初始化操作
 * @Author scyking
 * @Date 2019/1/23 16:32
 * @Version 1.0
 */
@Component
public class InitApplicationRunner implements ApplicationRunner {

    protected Logger logger = LoggerFactory.getLogger(getClass());

    @Value("${user.define.crypto.useToken}")
    public String useToken;

    @Value("${user.define.crypto.keyfile}")
    public String keyfile;

    @Value("${user.define.crypto.password}")
    public String password;

    @Value("${user.define.crypto.alias}")
    public String alias;



    @Autowired
    private RedisTemplate redisTemplate;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        logger.info("init...");
        Security.addProvider(new BouncyCastleProvider());

        File f = new File(keyfile);

        if(f.exists()){
            //load into buffer
            logger.info("load keys...");
            if (useToken.toLowerCase().contains("false")) {
                KeyStore pkcs12 = KeyStore.getInstance("PKCS12", "BC");
                pkcs12.load(new FileInputStream(keyfile), password.toCharArray());
                BCECPrivateKey privateKey = (BCECPrivateKey)pkcs12.getKey(alias, null);
                Certificate[] pubCerts = pkcs12.getCertificateChain(alias);

            }else{
                // TODO: use token

            }
            logger.info("init end !");
            return;
        }

        // the first time , generate key
        logger.info("generate keys...");
        if (useToken.toLowerCase().contains("false")) {

            //generate sm2 key
            try
            {
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");
                g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
                KeyPair p = g.generateKeyPair();
                BCECPrivateKey privateKey = (BCECPrivateKey)p.getPrivate();
                //save to file
                X509Certificate cert = null;
                try {
                    cert = generateV3CertificateSM2(p);

                }catch (Exception e){
                    logger.info("generate cert error : " + e.getMessage());
                    return;
                }
                try {
                    saveAsP12(p.getPrivate(), cert);
                }catch (Exception e){
                    logger.info("save p12 error : " + e.getMessage());
                    return;
                }

            }
            catch (Exception e)
            {
                e.printStackTrace();
                return;
            }



        }else{
            //TODO: generate keys by token



        }
        logger.info("init end !");
    }



    private  X509Certificate generateV3CertificateSM2( KeyPair rootkey) throws OperatorCreationException, CertIOException, NoSuchAlgorithmException, CertificateException {

        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.CN, "Root CA");
        nameBuilder.addRDN(BCStyle.C,"China");
        nameBuilder.addRDN(BCStyle.OU,"yuningit");
        nameBuilder.addRDN(BCStyle.O,"kmc");
        X500Name issuer = nameBuilder.build();
        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.setTime(notBefore);
        cal.add(Calendar.YEAR, 1);
        Date notAfter = cal.getTime();

        BigInteger serial = BigInteger.probablePrime(32, new Random());

        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(rootkey.getPrivate());

        JcaX509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                issuer,
                rootkey.getPublic());

        // extensions
        certGen.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints,
                        true, new BasicConstraints(true));

        certGen.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature ));
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));

        return cert;

    }


    private  void saveAsP12(PrivateKey privKey, X509Certificate cert) throws NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        java.security.cert.Certificate[] chain = new Certificate[1];
        chain[0] = cert;
        KeyStore store = null;
        store = KeyStore.getInstance("PKCS12", "BC");
        store.load(null, null);
        store.setKeyEntry(alias, privKey, null, chain);

        char[] passwd = password.toCharArray();
        store.store(new FileOutputStream(keyfile), passwd);

    }
}
