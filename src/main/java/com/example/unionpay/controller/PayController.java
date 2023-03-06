package com.example.unionpay.controller;




import com.example.unionpay.service.PayService;
import com.example.unionpay.service.UnionPaymentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author 鑫
 * @Date 2021/3/27 0027 16:56
 */
@RestController
public class PayController {

    @Autowired
    private UnionPaymentService service;

    @Autowired
    private PayService payService;

    @RequestMapping("/pay")
    public String pay(){
        String pay = payService.pay();
        return pay;
    }

    @RequestMapping("/ACPSample_DaiFu/frontRcvResponse")
    public String backRcvResponse(){
//        String pay = payService.pay();
        return "se";
    }

    /**
     * 后台回调
     * @param request
     * @param response
     * @throws IOException
     */
    @RequestMapping(value = "/backRcvResponse", method = {RequestMethod.GET, RequestMethod.POST})
    public void backRcvResponse(HttpServletRequest request, HttpServletResponse response) throws IOException, IOException {
        service.backRcvResponse(request, response);

    }

}

