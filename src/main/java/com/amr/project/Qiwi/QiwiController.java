package com.amr.project.Qiwi;

import com.amr.project.dao.OrderRepository;
import com.amr.project.model.entity.Order;
import com.qiwi.billpayments.sdk.model.out.BillResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/")
public class  QiwiController {
    private final QiwiService qiwiService;
    private final OrderRepository orderService;

    public QiwiController(QiwiService qiwiService, OrderRepository orderService) {
        this.qiwiService = qiwiService;
        this.orderService = orderService;
    }

    @GetMapping("/order/pay/{id}")
    public String payOrder(@PathVariable Long id){
        BillResponse billResponse = qiwiService.createBill(2, id,"test pay",
                "test@test.com", "79251234123", "http://localhost:8080/");
        String redirectUrl = billResponse.getPayUrl();
        return "redirect:" + redirectUrl;
    }

    @GetMapping("order/checkPay/{id}")
    public String payChek(@PathVariable(name = "id") Long id){
        String qiwiId = orderService.getById(id).getQiwiId();
        System.out.println(qiwiService.paymentStatus(qiwiId));
        return "redirect:/";
    }
}
