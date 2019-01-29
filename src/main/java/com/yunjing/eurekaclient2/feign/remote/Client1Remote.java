package com.yunjing.eurekaclient2.feign.remote;

import com.yunjing.eurekaclient2.common.base.ResultInfo;
import com.yunjing.eurekaclient2.feign.hystrix.Client1RemoteHystrix;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * 服务远程调用
 *
 * <p>
 *
 * @FeignClient name值为注册中心注册服务名，fallback为请求失败回调类
 * </p>
 */
@FeignClient(name = "pms-kmc", fallback = Client1RemoteHystrix.class)
public interface Client1Remote {


    @GetMapping("/key")
    ResultInfo getKey(String userID, int keyID);
}
