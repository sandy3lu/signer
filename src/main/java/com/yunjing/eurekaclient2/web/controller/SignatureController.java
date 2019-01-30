package com.yunjing.eurekaclient2.web.controller;
import com.yunjing.eurekaclient2.common.base.ResultInfo;
import com.yunjing.eurekaclient2.web.service.SignatureService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

/**
 * <p>
 * key管理表 前端控制器
 * </p>
 *
 * @author scyking-auto
 * @since 2019-01-28
 */
@RestController
@RequestMapping("/v1.0")
@Api("签名验签")
public class SignatureController {

    @Autowired
    SignatureService signatureService;

    @PostMapping("/signaturewithid")
    @ApiOperation("签名")
    public ResultInfo sign(@RequestParam("userId")String userID,@RequestParam("content") String content,@RequestParam("keyID") int keyID){
            byte[] data = Base64.getUrlDecoder().decode(content);
          try {
              byte[] result=signatureService.sign(userID, keyID, data);
               String s = Base64.getUrlEncoder().encodeToString(result);
                return ResultInfo.ok().put("data", s);
        }catch (Exception e){
            ResultInfo resultInfo = ResultInfo.error(e.getMessage());
            return resultInfo;
        }

    }

    @PostMapping("/signaturewithkeys")
    @ApiOperation("签名")
    public ResultInfo signWithKey(@RequestParam("content") String content,@RequestParam("algorithmID") String algorithmID,@RequestParam("privateKey") String privateKey,@RequestParam("publicKey") String publicKey){
        byte[] data = Base64.getUrlDecoder().decode(content);
        switch (algorithmID){
            case SignatureService.SM2:
            case SignatureService.RSA:
                try {
                    byte[] result=signatureService.sign(algorithmID, privateKey, publicKey,data);
                    String s = Base64.getUrlEncoder().encodeToString(result);
                    return ResultInfo.ok().put("data", s);
                }catch (Exception e){
                    ResultInfo resultInfo = ResultInfo.error(e.getMessage());
                    return resultInfo;
                }
                default:
                    return ResultInfo.error("not support algorithmID " + algorithmID);
        }


    }

    @GetMapping("/verification")
    @ApiOperation("验证签名")
    public ResultInfo verify(@RequestParam(name="content") String content,@RequestParam(name="signature") String signature,@RequestParam(name="algorithmID") String algorithmID,@RequestParam(name="publicKey") String publicKey) {
        byte[] data = Base64.getUrlDecoder().decode(content);
        byte[] sig = Base64.getUrlDecoder().decode(signature);
        switch (algorithmID) {
            case SignatureService.SM2:
            case SignatureService.RSA:
                try {
                    boolean result = signatureService.verify(algorithmID, publicKey, data, sig);
                    return ResultInfo.ok().put("verification", result);

                } catch (Exception e) {
                    ResultInfo resultInfo = ResultInfo.error(e.getMessage());
                    return resultInfo;
                }
            default:
                return ResultInfo.error("not support algorithmID " + algorithmID);
        }

    }

}
