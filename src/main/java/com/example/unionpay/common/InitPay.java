package com.example.unionpay.common;



import com.example.unionpay.sdk.SDKConfig;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * @author 鑫
 * @Date 2021/3/27 0027 16:48
 */
@Component
public class InitPay implements ApplicationRunner {
    @Override
    public void run(ApplicationArguments args) throws Exception {
        SDKConfig.getConfig().loadPropertiesFromSrc();
    }
}

