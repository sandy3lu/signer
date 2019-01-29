package com.yunjing.eurekaclient2.web.controller;


import com.yunjing.eurekaclient2.common.base.ResultInfo;
import com.yunjing.eurekaclient2.web.entity.Key;
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

    @PostMapping("/signature")
    @ApiOperation("签名")
    public ResultInfo generateKey(@RequestParam("userId")String userID,@RequestParam(name="content") String content,@RequestParam(name="keyID") int keyID,@RequestParam(name="algorithmID") String algorithmID,
                                  @RequestParam(name="keyContent") String keyContent,@RequestParam(name="publicKey") String publicKey){
            byte[] data = Base64.getUrlDecoder().decode(content);
          try {
              byte[] result=null;
              if(keyContent==null){
                   result = signatureService.sign(userID, keyID, data);
              }else{
                   result = signatureService.sign(algorithmID, keyContent, publicKey,data);
              }
                
               String s = Base64.getUrlEncoder().encodeToString(result);
                return ResultInfo.ok().put("data", s);
        }catch (Exception e){
            ResultInfo resultInfo = ResultInfo.error(e.getMessage());
            return resultInfo;
        }

    }

    @GetMapping("/verification")
    @ApiOperation("验证签名")
    public ResultInfo getKey(@RequestParam(name="content") String content,@RequestParam(name="signature") String signature,@RequestParam(name="algorithmID") String algorithmID,@RequestParam(name="publicKey") String publicKey){
        byte[] data = Base64.getUrlDecoder().decode(content);
        byte[] sig = Base64.getUrlDecoder().decode(signature);
        try{
            boolean result = signatureService.verify(algorithmID,publicKey,data, sig);
            return ResultInfo.ok().put("verification", result);

        }catch (Exception e){
            ResultInfo resultInfo = ResultInfo.error(e.getMessage());
            return resultInfo;
        }

    }



}
