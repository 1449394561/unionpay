package com.example.unionpay.service;



import com.example.unionpay.sdk.*;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigDecimal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by gangsun on 2017/4/12.
 */
@Service
public class UnionPaymentServiceImpl implements UnionPaymentService {

    @PostConstruct
    public void  init(){
        System.out.println("银联支付初始化");
        SDKConfig.getConfig().loadPropertiesFromSrc(); //从classpath加载acp_sdk.properties文件
        CertUtil.init();
    }


    /**
     * 后台回调
     * @param request
     * @param response
     */
    @Override
    public void backRcvResponse(HttpServletRequest request, HttpServletResponse response) throws IOException {
        LogUtil.writeLog("BackRcvResponse接收后台通知开始");

        String encoding = request.getParameter(SDKConstants.param_encoding);
        // 获取银联通知服务器发送的后台通知参数
        Map<String, String> reqParam = getAllRequestParam(request);

        LogUtil.printRequestLog(reqParam);

        Map<String, String> valideData = null;
        if (null != reqParam && !reqParam.isEmpty()) {
            Iterator<Map.Entry<String, String>> it = reqParam.entrySet().iterator();
            valideData = new HashMap<String, String>(reqParam.size());
            while (it.hasNext()) {
                Map.Entry<String, String> e = it.next();
                String key = (String) e.getKey();
                String value = (String) e.getValue();
                value = new String(value.getBytes(encoding), encoding);
                valideData.put(key, value);
            }
        }

        //重要！验证签名前不要修改reqParam中的键值对的内容，否则会验签不过
        if (!AcpService.validate(valideData, encoding)) {
            LogUtil.writeLog("验证签名结果[失败].");
            //验签失败，需解决验签问题

        } else {
            LogUtil.writeLog("验证签名结果[成功].");
            //【注：为了安全验签成功才应该写商户的成功处理逻辑】交易成功，更新商户订单状态

            String orderId =valideData.get("orderId"); //获取后台通知的数据，其他字段也可用类似方式获取
            String orderSn =orderId; //orderId其实存的是Sn

            String respCode = valideData.get("respCode");
            String txnAmt = valideData.get("txnAmt");
            BigDecimal txnAmount = (new BigDecimal(txnAmt)).multiply(new BigDecimal(0.01));

            String queryId = valideData.get("queryId");
            String traceTime = valideData.get("traceTime");
            String payCardNo = valideData.get("payCardNo");
            String payCardType = valideData.get("payCardType"); //支付卡类型
            String paymentMethodMethod; //PayPaymentMethod里面的method字段
            if(StringUtils.isEmpty(payCardType)){
                paymentMethodMethod = "UNION";  //对之前代码做兼容，如果没有支付卡类型的情况走默认
            }else{
                paymentMethodMethod = "UNION-" + payCardType;
            }

            //判断respCode=00、A6后，对涉及资金类的交易，请再发起查询接口查询，确定交易成功后更新数据库。
            if("00".equals(respCode)){  // 00 交易成功

                //todo 若交易成功
            }else if("A6".equals(respCode)){  // A6 部分成功

            }

        }
        LogUtil.writeLog("BackRcvResponse接收后台通知结束");
        //返回给银联服务器http 200  状态码
        response.getWriter().print("ok");
    }






    //---------------------------------------------------- private -----------------------------------------------------

    /**
     * 获取请求参数中所有的信息
     *
     * @param request
     * @return
     */
    private static Map<String, String> getAllRequestParam(final HttpServletRequest request) {
        Map<String, String> res = new HashMap<String, String>();
        Enumeration<?> temp = request.getParameterNames();
        if (null != temp) {
            while (temp.hasMoreElements()) {
                String en = (String) temp.nextElement();
                String value = request.getParameter(en);
                res.put(en, value);
                //在报文上送时，如果字段的值为空，则不上送<下面的处理为在获取所有参数数据时，判断若值为空，则删除这个字段>
                //System.out.println("ServletUtil类247行  temp数据的键=="+en+"     值==="+value);
                if (null == res.get(en) || "".equals(res.get(en))) {
                    res.remove(en);
                }
            }
        }
        return res;
    }



    //收费比率 精确到分保留两位小数四舍五入
    private BigDecimal getFeeAmount(BigDecimal amount, BigDecimal feeRatio, BigDecimal feeMax) {
        BigDecimal fee = new BigDecimal(0);
        if(null == amount || null == feeRatio) return fee;
        //金额乘以费率 = 手续费
        fee = amount.multiply(feeRatio);
        //最大值为feeMax
        if(null != feeMax && feeMax.compareTo(new BigDecimal("0")) >= 0) fee = fee.max(feeMax);
        //设置精确到分并四舍五入
        fee = fee.setScale(4, BigDecimal.ROUND_HALF_UP);
        return fee;
    }

    /**
     * 时间格式化
     * @param date
     * @return
     */
    private static String formatTime(Date date){
        return new SimpleDateFormat("yyyyMMddHHmmss").format(date);
    }
    private static Date formatTime(String dateStr){
        if(null == dateStr) return null;
        if(dateStr.length() == 14){
            try {
                return new SimpleDateFormat("yyyyMMddHHmmss").parse(dateStr);
            } catch (ParseException e) {
                e.printStackTrace();
                return null;
            }
        }else{
            try {
                return new SimpleDateFormat("MMddHHmmss").parse(dateStr);
            } catch (ParseException e) {
                e.printStackTrace();
                return null;
            }

        }

    }


}
