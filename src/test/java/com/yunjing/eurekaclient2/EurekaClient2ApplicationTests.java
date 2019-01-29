package com.yunjing.eurekaclient2;


import com.yunjing.eurekaclient2.web.entity.DictConstant;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class EurekaClient2ApplicationTests {

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @Autowired
    private RedisTemplate redisTemplate;

    @Test
    public void contextLoads() {
    }



    /***
     * redis测试
     * @throws Exception
     */
    @Test
    public void testRedis() throws Exception {
        // set
        stringRedisTemplate.opsForValue().set("key", "value");
        // get
        String value = stringRedisTemplate.opsForValue().get("key");
        Assert.assertEquals("value", value);
    }

    /***
     * redis测试
     * @throws Exception
     */
    @Test
    public void testRedisObj() throws Exception {
        DictConstant dictConstant = new DictConstant();
        dictConstant.setId(1);
        dictConstant.setValue("test");

        ValueOperations<String, DictConstant> operations = redisTemplate.opsForValue();
        // set
        operations.set("obj.dict.key", dictConstant);
        // get
        DictConstant dictConstant2 = operations.get("obj.dict.key");

        Assert.assertEquals(dictConstant.getId(), dictConstant2.getId());
        Assert.assertEquals(dictConstant.getValue(), dictConstant2.getValue());
    }

}

