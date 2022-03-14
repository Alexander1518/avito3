package com.amr.project.webapp.controller;

import com.amr.project.converter.mappers.ItemMapper;
import com.amr.project.converter.lists.ItemListMapper;
import com.amr.project.model.dto.ItemDTO;
import com.amr.project.model.entity.Item;
import com.amr.project.service.abstracts.ItemService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;


import java.util.List;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
public class ItemController {


    private static final Logger logger = LoggerFactory.getLogger(ItemController.class);
    private static final String ID = "itemId";
    private static final String NEW_ITEM_LOG = "New item was created id:{}";
    private static final String ITEM_UPDATED_LOG = "Item:{} was updated";
    private static final String GET_ITEM_LOG = "Item:{} is get";




    private final ItemService itemService;

    @Autowired
    public ItemController(ItemService itemService) {
        this.itemService = itemService;
    }

    @GetMapping("/items")
    public ResponseEntity<List<ItemDTO>> getAllItems() {
        List<Item> items = itemService.getAllItems();

        List<ItemDTO> itemDTOS = ItemListMapper.INSTANCE.toDTOList(items);
        logger.info(GET_ITEM_LOG);
        return new ResponseEntity<>(itemDTOS, HttpStatus.OK);
    }

    @GetMapping("/items/{id}")
    public ResponseEntity<ItemDTO> getItem(@PathVariable(name = "id") Long id) {
        ItemDTO itemDTO = ItemMapper.INSTANCE.toDTO(itemService.getItemById(id));
        return new ResponseEntity<>(itemDTO, HttpStatus.OK);
    }


    @Operation(summary = "Create a new Item")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201",
                    description = "Item is created",
                    content = @Content(mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ItemDTO.class)))
    })

    @PostMapping("/items")
    public ResponseEntity<ItemDTO> addItem(@RequestBody ItemDTO itemDTO) {
        Item item = ItemMapper.INSTANCE.toEntity(itemDTO);
        itemService.saveItem(item);
        ItemDTO dto = ItemMapper.INSTANCE.toDTO(item);
        logger.info(NEW_ITEM_LOG, dto.toString());
        return new ResponseEntity<>(dto, HttpStatus.CREATED);
    }




    @Operation(summary = "Update an Item by its ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200",
                    description = "Item was updated",
                    content = @Content(mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ItemDTO.class))),
            @ApiResponse(responseCode = "404",
                    description = "Item not found",
                    content = @Content)
    })
    @PatchMapping("/items/{id}")
    public ResponseEntity<ItemDTO> editItem(
            @PathVariable(name = "id") Long id,
            @RequestBody ItemDTO itemDTO) {
        Item item = ItemMapper.INSTANCE.toEntity(itemDTO);
        itemService.updateItem(item);
        ItemDTO dto = ItemMapper.INSTANCE.toDTO(item);
        logger.info(ITEM_UPDATED_LOG, dto.toString());
        return new ResponseEntity<>(dto, HttpStatus.OK);
    }




    @Operation(summary = "Delete an Item by its ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200",
                    description = "Item was updated",
                    content = @Content(mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ItemDTO.class))),
            @ApiResponse(responseCode = "404",
                    description = "Item not found",
                    content = @Content)
    })
    @DeleteMapping("/items/admin/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Long> deleteItem(@PathVariable(name = "id") Long id) {
        Item item = itemService.getItemById(id);
        itemService.deleteItem(id);
        logger.info("Deleted Item");
        return new ResponseEntity<>(id, HttpStatus.OK);
    }





    @Operation(summary = "Mark item as pretended to delete")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200",
                    description = "Item was updated",
                    content = @Content(mediaType = APPLICATION_JSON_VALUE,
                            schema = @Schema(implementation = ItemDTO.class))),
            @ApiResponse(responseCode = "404",
                    description = "Item not found",
                    content = @Content)
    })
    @DeleteMapping("/items/user/{id}")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR')")
    public ResponseEntity<ItemDTO> deleteAdminItem(@PathVariable(name = "id") Long id) {

        Item item = itemService.getItemById(id);
        item.setPretendedToBeDeleted(true);
        ItemDTO itemDTO = ItemMapper.INSTANCE.toDTO(item);
        logger.info("At pretended to delete");
        return new ResponseEntity<>(itemDTO, HttpStatus.OK);

    }
}
