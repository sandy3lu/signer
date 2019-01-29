package com.yunjing.eurekaclient2.web.service;

import com.yunjing.eurekaclient2.web.entity.Key;
import com.baomidou.mybatisplus.extension.service.IService;
import org.bouncycastle.crypto.CryptoException;

import java.io.IOException;


/**
 * <p>
 * key管理表 服务类
 * </p>
 *
 * @author scyking-auto
 * @since 2019-01-28
 */
public interface SignatureService extends IService<Key> {


    String SM2 = "SM2";
    String RSA = "RSA2048";


    boolean verify(String algorithmID, String publicKey, byte[] data, byte[] sig) throws IOException;

    byte[] sign(String userID, int keyID, byte[] data) throws IOException, CryptoException;

    byte[] sign(String algorithmID, String privateKey, String publicKey, byte[] data) throws IOException, CryptoException;
}

