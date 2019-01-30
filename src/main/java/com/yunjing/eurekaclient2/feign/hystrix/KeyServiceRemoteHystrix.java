package com.yunjing.eurekaclient2.feign.hystrix;

import com.yunjing.eurekaclient2.common.base.ResultInfo;
import com.yunjing.eurekaclient2.feign.remote.KeyServiceRemote;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @ClassName Client1RemoteHystrix
 * @Description 回调类
 * @Author scyking
 * @Date 2019/1/21 16:23
 * @Version 1.0
 */
@Component
public class KeyServiceRemoteHystrix {


    public ResultInfo getKey(@RequestParam("userId")String userID, @RequestParam(name="keyID") int keyID) {
        return ResultInfo.error("could not get pms-kmc service!");
    }
}
