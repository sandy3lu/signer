package com.yunjing.eurekaclient2;

import com.baomidou.mybatisplus.generator.AutoGenerator;
import com.baomidou.mybatisplus.generator.config.DataSourceConfig;
import com.baomidou.mybatisplus.generator.config.GlobalConfig;
import com.baomidou.mybatisplus.generator.config.PackageConfig;
import com.baomidou.mybatisplus.generator.config.StrategyConfig;
import com.baomidou.mybatisplus.generator.config.rules.NamingStrategy;
import com.baomidou.mybatisplus.generator.engine.FreemarkerTemplateEngine;

/**
 * @ClassName CodeGenerator
 * @Description 自动代码生成
 * @Author scyking
 * @Date 2019/1/23 11:48
 * @Version 1.0
 */
public class CodeGenerator {

    // 需生成的表
    public static String[] tables = {"key"};
    // 模块名
    public static String moduleName = "web";

    public static void main(String[] args) {
        // 代码生成器
        AutoGenerator mpg = new AutoGenerator();
        // 切换为 freemarker 模板引擎
        mpg.setTemplateEngine(new FreemarkerTemplateEngine());

        // 全局配置
        GlobalConfig gc = new GlobalConfig();
        // gc.setOutputDir("E:/works/sublime/eureka-client-2/src/main/java"); // 根据自己工程进行修改
        gc.setOutputDir("F:/PaaS/code/eureka-client-2/auto"); // 不建议直接覆盖工程中代码。自动生成后，手动复制
        gc.setAuthor("scyking-auto"); // 注释中作者信息
        gc.setOpen(false);
        // 自定义文件命名。（%s 会自动填充表实体属性）
        gc.setMapperName("%sMapper");
        gc.setXmlName("%sExdMapper");
        gc.setServiceName("%sService");
        gc.setServiceImplName("%sServiceImpl");
        gc.setControllerName("%sController");
        mpg.setGlobalConfig(gc);

        // 数据源配置
        DataSourceConfig dsc = new DataSourceConfig();
        dsc.setUrl("jdbc:mysql://192.168.20.16:3306/pms_kmc?useSSL=false&useUnicode=true&characterEncoding=utf8&serverTimezone=GMT%2B8");
        dsc.setDriverName("com.mysql.cj.jdbc.Driver");
        dsc.setUsername("kmc");
        dsc.setPassword("kmc");
        mpg.setDataSource(dsc);

        // 包配置
        PackageConfig pc = new PackageConfig();
        pc.setParent("com.yunjing.eurekaclient2");
        pc.setModuleName(moduleName);

        mpg.setPackageInfo(pc);

        // 策略配置
        StrategyConfig strategy = new StrategyConfig();
        strategy.setNaming(NamingStrategy.underline_to_camel);
        strategy.setColumnNaming(NamingStrategy.underline_to_camel);
        strategy.setSuperEntityClass("com.yunjing.eurekaclient2.common.base.BaseEntity"); // 实体继承的根类
        strategy.setEntityLombokModel(true);
        strategy.setRestControllerStyle(true);
        strategy.setInclude(tables);
        // 自定义实体，公共字段
        strategy.setSuperEntityColumns(new String[]{"id"});
        strategy.setControllerMappingHyphenStyle(true);
        strategy.setTablePrefix(pc.getModuleName() + "_");
        mpg.setStrategy(strategy);

        // 执行生成
        mpg.execute();
    }
}
