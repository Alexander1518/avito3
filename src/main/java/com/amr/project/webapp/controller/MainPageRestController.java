package com.amr.project.webapp.controller;

import com.amr.project.model.dto.*;
import com.amr.project.service.abstracts.CategoryService;
import com.amr.project.service.abstracts.ItemService;
import com.amr.project.service.abstracts.ShopService;
import com.amr.project.service.abstracts.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.amr.project.converter.CycleAvoidingMappingContext;
import org.springframework.data.domain.Pageable;

import java.security.Principal;

@RestController
@RequiredArgsConstructor
@RequestMapping("/main")
@CrossOrigin
public class MainPageRestController {

    private final ItemService itemService;
    private final ShopService shopService;
    private final CategoryService categoryService;



    @GetMapping("/search")
    public ResponseEntity<ItemShopDto> getShopAndItems(
            @RequestParam("shopOrItemName") String shopOrItemName, Pageable pageable) {
        if (shopOrItemName == null) {
            return new ResponseEntity<>(new ItemShopDto(shopService.getAllShops(),
                    itemService.getAllItems()), HttpStatus.OK);
        }
        ItemShopDto itemShopDto = new ItemShopDto(
                shopService.searchShopsByNameSortedByRatingDesc(shopOrItemName, pageable),
                itemService.searchItemsByNameSortedByRatingDesc(shopOrItemName, pageable));
        return new ResponseEntity<>(itemShopDto, HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity<MainPageDto> getMainPage() {
        MainPageDto mainPageDto = new MainPageDto(categoryService.getAllCategories(),
                shopService.findFirst4ByOrderByRatingDesc(),
                itemService.findFirst4ByOrderByRatingDesc());
        return new ResponseEntity<>(mainPageDto, HttpStatus.OK);
    }
}
