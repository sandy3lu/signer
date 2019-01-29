package com.yunjing.eurekaclient2.web.entity;

import com.yunjing.eurekaclient2.common.base.BaseEntity;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.Accessors;

/**
 * <p>
 * 通用字典表
 * </p>
 *
 * @author scyking-auto
 * @since 2019-01-23
 */
@Data
@EqualsAndHashCode(callSuper = true)
@Accessors(chain = true)
public class DictConstant extends BaseEntity {

    private static final long serialVersionUID = 1L;

    /**
     * 常量名称
     */
    private String value;

    /**
     * 父id
     */
    private Integer parentId;


}
