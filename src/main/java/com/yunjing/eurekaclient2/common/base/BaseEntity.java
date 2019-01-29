package com.yunjing.eurekaclient2.common.base;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Getter;
import lombok.Setter;

/**
 * @ClassName BaseEntity
 * @Description 实体根类
 * @Author scyking
 * @Date 2019/1/23 17:23
 * @Version 1.0
 */
public class BaseEntity {

    @TableId(type = IdType.AUTO)
    @Getter
    @Setter
    private Integer id;
}
