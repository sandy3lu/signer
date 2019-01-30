package com.yunjing.eurekaclient2.feign.remote;

import com.yunjing.eurekaclient2.common.base.ResultInfo;
import com.yunjing.eurekaclient2.feign.hystrix.KeyServiceRemoteHystrix;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 服务远程调用
 *
 * <p>
 *
 * @FeignClient name值为注册中心注册服务名，fallback为请求失败回调类
 * </p>
 */
@FeignClient(name = "pms-kmc")
public interface KeyServiceRemote {


    @GetMapping("/v1.0/key")
    ResultInfo getKey(@RequestParam("userId") final String userID, @RequestParam(name="keyID") final int keyID);
}
