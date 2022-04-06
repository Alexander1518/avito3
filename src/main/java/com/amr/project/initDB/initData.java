package com.amr.project.initDB;

import com.amr.project.dao.*;
import com.amr.project.model.entity.*;
import com.amr.project.model.enums.Gender;
import com.amr.project.model.enums.Roles;
import com.amr.project.model.enums.Status;
import com.amr.project.webapp.config.security.handler.PassEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.*;


@Component
public class initData {

    private final ReviewRepository reviewRepository;
    private final OrderRepository ordersRepository;
    private final ItemRepository itemRepository;
    private final FeedbackRepository feedBackRepository;
    private final FavoriteRepository favoriteRepository;
    private final DiscountRepository discountRepository;
    private final CouponRepository couponRepository;
    private final CityRepository cityRepository;
    private final ChatRepository chatRepository;
    private final CategoryRepository categoryRepository;
    private final UserRepository userRepository;
    private final ShopRepository shopRepository;
    private final AddressRepository addressRepository;
    private final UserInfoRepository userInfoRepository;
    private final CartItemRepository cartItemRepository;
    private final MessageRepository messageRepository;
    private final ImageRepository imageRepository;
    private final CountryRepository countryRepository;
    private final PassEncoder passwordEncoder;

    @Autowired
    public initData(ReviewRepository reviewRepository, OrderRepository ordersRepository,
                    ItemRepository itemRepository, FeedbackRepository feedBackRepository,
                    FavoriteRepository favoriteRepository, DiscountRepository discountRepository,
                    CouponRepository couponRepository,
                    CityRepository cityRepository, ChatRepository chatRepository,
                    CategoryRepository categoryRepository, UserRepository userRepository,
                    ShopRepository shopRepository, AddressRepository addressRepository,
                    UserInfoRepository userInfoRepository, CartItemRepository cartItemRepository,
                    MessageRepository messageRepository, ImageRepository imageRepository,
                    CountryRepository countryRepository, PassEncoder passwordEncoder) {
        this.reviewRepository = reviewRepository;
        this.ordersRepository = ordersRepository;
        this.itemRepository = itemRepository;
        this.feedBackRepository = feedBackRepository;
        this.favoriteRepository = favoriteRepository;
        this.discountRepository = discountRepository;
        this.couponRepository = couponRepository;
        this.cityRepository = cityRepository;
        this.chatRepository = chatRepository;
        this.categoryRepository = categoryRepository;
        this.userRepository = userRepository;
        this.shopRepository = shopRepository;
        this.addressRepository = addressRepository;
        this.userInfoRepository = userInfoRepository;
        this.cartItemRepository = cartItemRepository;
        this.messageRepository = messageRepository;
        this.imageRepository = imageRepository;
        this.countryRepository = countryRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initializationDB() throws IOException {
        /////////////////////////////////////////////////Images////////////////////////////////////////////////////////////
        File item1_image = ResourceUtils.getFile("classpath:static/images/items/item1.jpg");
        byte[] arrayItemImage1 = Files.readAllBytes(item1_image.toPath());
        //Image itemImage1 = Image.builder().picture(arrayItemImage1).isMain(true).build();

        Image itemImage1 = new Image();
        itemImage1.setPicture(arrayItemImage1);

        File item2_image = ResourceUtils.getFile("classpath:static/images/items/item2.jpg");
        byte[] arrayItemImage2 = Files.readAllBytes(item2_image.toPath());
        Image itemImage2 = Image.builder().picture(arrayItemImage2).isMain(true).build();
        File item3_image = ResourceUtils.getFile("classpath:static/images/items/item3.jpg");
        byte[] arrayItemImage3 = Files.readAllBytes(item3_image.toPath());
        Image itemImage3 = Image.builder().picture(arrayItemImage3).isMain(true).build();
        File item4_image = ResourceUtils.getFile("classpath:static/images/items/item4.jpg");
        byte[] arrayItemImage4 = Files.readAllBytes(item4_image.toPath());
        Image itemImage4 = Image.builder().picture(arrayItemImage4).isMain(true).build();
        imageRepository.save(itemImage1); //Data truncation: Data too long for column 'picture' at row 1/@Lob
        imageRepository.save(itemImage2);
        imageRepository.save(itemImage3);
        imageRepository.save(itemImage4);

        File shop1_image = ResourceUtils.getFile("classpath:static/images/shopLogo/shop1.jpg");
        byte[] arrayShopImage1 = Files.readAllBytes(shop1_image.toPath());
        Image shopImage1 = Image.builder().picture(arrayShopImage1).isMain(true).build();
        File shop2_image = ResourceUtils.getFile("classpath:static/images/shopLogo/shop2.jpg");
        byte[] arrayShopImage2 = Files.readAllBytes(shop2_image.toPath());
        Image shopImage2 = Image.builder().picture(arrayShopImage2).isMain(true).build();
        File shop3_image = ResourceUtils.getFile("classpath:static/images/shopLogo/shop3.jpg");
        byte[] arrayShopImage3 = Files.readAllBytes(shop3_image.toPath());
        Image shopImage3 = Image.builder().picture(arrayShopImage3).isMain(true).build();
        imageRepository.save(shopImage1);
        imageRepository.save(shopImage2);
        imageRepository.save(shopImage3);

        File logo1_image = ResourceUtils.getFile("classpath:static/images/logo/logo1.jpg");
        byte[] arrayLogoImage1 = Files.readAllBytes(logo1_image.toPath());
        Image logoImage1 = Image.builder().picture(arrayLogoImage1).isMain(true).build();
        imageRepository.save(logoImage1);

//        File user_avatar1 = ResourceUtils.getFile("classpath:static/images/userAvatar/avatar1.jpg");
//        byte[] arrayUserAvatar1 = Files.readAllBytes(user_avatar1.toPath());
//        Image userAvatar1 = Image.builder().picture(arrayUserAvatar1).isMain(true).build();
//        imageRepository.save(userAvatar1);
//        File user_avatar2 = ResourceUtils.getFile("classpath:static/images/userAvatar/avatar2.jpg");
//        byte[] arrayUserAvatar2 = Files.readAllBytes(user_avatar2.toPath());
//        Image userAvatar2 = Image.builder().picture(arrayUserAvatar2).isMain(true).build();
//        imageRepository.save(userAvatar2);
//        File user_avatar3 = ResourceUtils.getFile("classpath:static/images/userAvatar/avatar3.jpg");
//        byte[] arrayUserAvatar3 = Files.readAllBytes(user_avatar3.toPath());
//        Image userAvatar3 = Image.builder().picture(arrayUserAvatar3).isMain(true).build();
//        imageRepository.save(userAvatar1);

//        List<Image> imageList = new ArrayList<>();
//        imageList.add(imageRepository.findByPicture(arrayUserAvatar1));
//        imageList.add(imageRepository.findByPicture(arrayUserAvatar2));



/////////////////////////////////////////////////Country////////////////////////////////////////////////////////////
        Country USA = new Country();
        USA.setName("USA");
        Country Germany = new Country();
        Germany.setName("Germany");
        countryRepository.save(USA);
        countryRepository.save(Germany);

/////////////////////////////////////////////////City////////////////////////////////////////////////////////////
        City Berlin = City.builder().name("Berlin").country(Germany).build();
        City LosSantos = City.builder().name("LosSantos").country(USA).build();
        City SanAndreas = City.builder().name("SanAndreas").country(USA).build();
        City Vegas = City.builder().name("Vegas").country(USA).build();
        City Frankfurt = City.builder().name("Frankfurt").country(Germany).build();
        cityRepository.save(Berlin);
        cityRepository.save(LosSantos);
        cityRepository.save(SanAndreas);
        cityRepository.save(Vegas);
        cityRepository.save(Frankfurt);

/////////////////////////////////////////////////Address////////////////////////////////////////////////////////////
        Address address1 = Address.builder()
                .city(Vegas)
                .cityIndex("123")
                .street("user1_street")
                .house("user1_house")
                .build();
        Address address2 = Address.builder()
                .city(LosSantos)
                .cityIndex("456")
                .street("user2_street")
                .house("user2_house")
                .build();
        Address address3 = Address.builder()
                .city(Berlin)
                .cityIndex("789")
                .street("user3_street")
                .house("user3_house")
                .build();
        addressRepository.save(address1);
        addressRepository.save(address2);
        addressRepository.save(address3);

/////////////////////////////////////////////////User////////////////////////////////////////////////////////////
        User user1 = User.builder()
                .email("user1@mail.com")
                .username("user1")
                .password(passwordEncoder.passwordEncoder().encode("user1"))
                .activate(true)
                .activationCode("some_code")
                .isUsing2FA(false)
                .secret("secret?")
                .role(Roles.USER)
                .userInfo(null)
                .favorite(null)
                .address(address1)
                .images(null)
                .coupons(null)
                .carts(null)
                .orders(null)
                .reviews(null)
                .shops(null)
                .discounts(null)
                .messages(null)
                .chats(null)
                .feedbacks(null)
                .build();
        User user2 = User.builder()
                .email("user2@mail.com")
                .username("user2")
                .password(passwordEncoder.passwordEncoder().encode("user2"))
                .activate(true)
                .activationCode("some_code")
                .isUsing2FA(false)
                .secret("secret?")
                .role(Roles.USER)
                .userInfo(null)
                .favorite(null)
                .address(null)
                .images(null)
                .coupons(null)
                .carts(null)
                .orders(null)
                .reviews(null)
                .shops(null)
                .discounts(null)
                .messages(null)
                .chats(null)
                .feedbacks(null)
                .build();
        User user3 = User.builder()
                .email("user3@mail.com")
                .username("user3")
                .password(passwordEncoder.passwordEncoder().encode("user3"))
                .activate(true)
                .activationCode("some_code")
                .isUsing2FA(false)
                .secret("secret?")
                .role(Roles.USER)
                .userInfo(null)
                .favorite(null)
                .address(null)
                .images(null)
                .coupons(null)
                .carts(null)
                .orders(null)
                .reviews(null)
                .shops(null)
                .discounts(null)
                .messages(null)
                .chats(null)
                .feedbacks(null)
                .build();
        userRepository.save(user1);
        userRepository.save(user2);
        userRepository.save(user3);

        User user4 = User.builder()
                .email("user4@mail.com")
                .username("user4")
                .password(passwordEncoder.passwordEncoder().encode("user4"))
                .activate(true)
                .activationCode("some_code")
                .isUsing2FA(false)
                .secret("secret?")
                .role(Roles.USER)
                .userInfo(null)
                .favorite(null)
                .address(null)
                .images(null)
                .coupons(null)
                .carts(null)
                .orders(null)
                .reviews(null)
                .shops(null)
                .discounts(null)
                .messages(null)
                .chats(null)
                .feedbacks(null)
                .build();
        userRepository.save(user4);


/////////////////////////////////////////////////Coupons////////////////////////////////////////////////////////////
//        User user1Coupons = userRepository.findByEmail("user1@mail.com");
//        User user2Coupons = userRepository.findByEmail("user2@mail.com");
//        User user3Coupons = userRepository.findByEmail("user3@mail.com");
        Coupon coupon1 = Coupon.builder()
                .start(Calendar.getInstance())
                .end(Calendar.getInstance())
                .user(user1)
                .build();
        Coupon coupon2 = Coupon.builder()
                .start(Calendar.getInstance())
                .end(Calendar.getInstance())
                .user(user2)
                .build();
        Coupon coupon3 = Coupon.builder()
                .start(Calendar.getInstance())
                .end(Calendar.getInstance())
                .user(user3)
                .build();
        couponRepository.save(coupon1);
        couponRepository.save(coupon2);
        couponRepository.save(coupon3);

/////////////////////////////////////////////////Shop////////////////////////////////////////////////////////////
        Shop shop1 = Shop.builder()
                .name("shop1")
                .email("shop1@mail.com")
                .phone("shop1_phone")
                .description("shop1_description")
                .count(0)
                .rating(0)
/*                .country(Germany)*/
                .items(null)
                .reviews(null)
                .logo(null)
                .user(user1)
                .cartItem(null)
                .feedbacks(null)
                .discounts(null)
                .favorites(null)
                .address(address1)
                .coupons(null)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("cozTest")
                .isPretendedToBeDeleted(false)
                .build();
        Shop shop2 = Shop.builder()
                .name("shop2")
                .email("shop2@mail.com")
                .phone("shop2_phone")
                .description("shop2_description")
                .count(0)
                .rating(0)
/*                .country(USA)*/
                .items(null)
                .reviews(null)
                .logo(null)
                .user(user2)
                .cartItem(null)
                .feedbacks(null)
                .discounts(null)
                .favorites(null)
                .address(address2)
                .coupons(null)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("cozTest")
                .isPretendedToBeDeleted(false)
                .build();
        Shop shop3 = Shop.builder()
                .name("shop3")
                .email("shop3@mail.com")
                .phone("shop3_phone")
                .description("shop3_description")
                .count(0)
                .rating(0)
/*                .country(USA)*/
                .items(null)
                .reviews(null)
                .logo(null)
                .user(user3)
                .cartItem(null)
                .feedbacks(null)
                .discounts(null)
                .favorites(null)
                .address(address3)
                .coupons(null)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("cozTest")
                .isPretendedToBeDeleted(false)
                .build();
        shopRepository.save(shop1);
        shopRepository.save(shop2);
        shopRepository.save(shop3);

/////////////////////////////////////////////////Category////////////////////////////////////////////////////////////
        Category category1 = Category.builder().name("cat1").build();
        Category category2 = Category.builder().name("cat2").build();
        Category category3 = Category.builder().name("cat3").build();
        Category category4 = Category.builder().name("cat4").build();
        Category category5 = Category.builder().name("cat5").build();
        categoryRepository.save(category1);
        categoryRepository.save(category2);
        categoryRepository.save(category3);
        categoryRepository.save(category4);
        categoryRepository.save(category5);

/////////////////////////////////////////////////Item////////////////////////////////////////////////////////////
        Item item1 = Item.builder()
                .name("item1")
                .basePrice(new BigDecimal(100))
                .price(new BigDecimal(210))
                .count(20)
                .rating(5.0)
                .description("description")
                .discount(0)
                .category(category1)
                .cartItem(null)
                .images(null) //detached entity passed to persist: com.amr.project.model.entity.Image
                .reviews(null)
                .favorites(null)
                .orders(null)
                .shop(shop1)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("coz")
                .isPretendedToBeDeleted(false)
                .build();
        Item item2 = Item.builder()
                .name("item2")
                .basePrice(new BigDecimal(200))
                .price(new BigDecimal(410))
                .count(20)
                .rating(5.0)
                .description("description")
                .discount(0)
                .category(category1)
                .cartItem(null)
                .images(null)
                .reviews(null)
                .favorites(null)
                .orders(null)
                .shop(shop1)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("coz")
                .isPretendedToBeDeleted(false)
                .build();
        Item item3 = Item.builder()
                .name("item3")
                .basePrice(new BigDecimal(500))
                .price(new BigDecimal(910))
                .count(10)
                .rating(3.0)
                .description("description")
                .discount(0)
                .category(category2)
                .cartItem(null)
                .images(null)
                .reviews(null)
                .favorites(null)
                .orders(null)
                .shop(shop1)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("coz")
                .isPretendedToBeDeleted(false)
                .build();
        Item item4 = Item.builder()
                .name("item4")
                .basePrice(new BigDecimal(900))
                .price(new BigDecimal(1800))
                .count(40)
                .rating(2.0)
                .description("description")
                .discount(0)
                .category(category2)
                .cartItem(null)
                .images(null)
                .reviews(null)
                .favorites(null)
                .orders(null)
                .shop(shop1)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("coz")
                .isPretendedToBeDeleted(false)
                .build();
        Item item5 = Item.builder()
                .name("item5")
                .basePrice(new BigDecimal(100))
                .price(new BigDecimal(210))
                .count(2000)
                .rating(3.0)
                .description("description")
                .discount(0)
                .category(category3)
                .cartItem(null)
                .images(null)
                .reviews(null)
                .favorites(null)
                .orders(null)
                .shop(shop1)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("coz")
                .isPretendedToBeDeleted(false)
                .build();
        Item item6 = Item.builder()
                .name("item6")
                .basePrice(new BigDecimal(100))
                .price(new BigDecimal(210))
                .count(200)
                .rating(4.0)
                .description("description")
                .discount(0)
                .category(category3)
                .cartItem(null)
                .images(null)
                .reviews(null)
                .favorites(null)
                .orders(null)
                .shop(shop1)
                .isModerated(true)
                .isModerateAccept(true)
                .moderatedRejectReason("coz")
                .isPretendedToBeDeleted(false)
                .build();
        itemRepository.save(item1);
        itemRepository.save(item2);
        itemRepository.save(item3);
        itemRepository.save(item4);
        itemRepository.save(item5);
        itemRepository.save(item6);

/////////////////////////////////////////////////FeedBack////////////////////////////////////////////////////////////
        Feedback feedback1 = Feedback.builder()
                .reason("reason1")
                .fullText("full_text_fb1")
                .dateTime(LocalDate.now().atTime(12, 33))
                .username(user1.getUsername())
                .shop(shop1)
                .user(user1)
                .build();
        Feedback feedback2 = Feedback.builder()
                .reason("reason2")
                .fullText("full_text_fb2")
                .dateTime(LocalDate.now().atTime(LocalTime.now()))
                .username(user2.getUsername())
                .shop(shop2)
                .user(user2)
                .build();
        feedBackRepository.save(feedback1);
        feedBackRepository.save(feedback2);

/////////////////////////////////////////////////Discounts////////////////////////////////////////////////////////////
        Discount discount1 = Discount.builder()
                .minOrder(1000)
                .percentage(5)
                .fixedDiscount(2)
                .shop(shop1)
                .build();
        Discount discount2 = Discount.builder()
                .minOrder(3500)
                .percentage(15)
                .fixedDiscount(2)
                .shop(shop2)
                .build();
        user1.setDiscounts(Set.of(discount1));
        discountRepository.save(discount1);
        discountRepository.save(discount2);

/////////////////////////////////////////////////Chat//////////message//////////////////////////////////////////////////
        Message message1_chat1 = Message.builder()
                .date(Date.from(Instant.now()))
                .textMessage("message1textChat1")
                .viewed(true)
                .user(user1)
                .chat(null)
                .build();
        Message message2_chat1 = Message.builder()
                .date(Date.from(Instant.now()))
                .textMessage("message2textChat1")
                .viewed(true)
                .user(user2)
                .chat(null)
                .build();

        Message message1_chat2 = Message.builder()
                .date(Date.from(Instant.now()))
                .textMessage("message1textChat2")
                .viewed(true)
                .user(user2)
                .chat(null)
                .build();
        Message message2_chat2 = Message.builder()
                .date(Date.from(Instant.now()))
                .textMessage("message2textChat2")
                .viewed(true)
                .user(user3)
                .chat(null)
                .build();
        Chat chat1 = Chat.builder().users(List.of(user1, user2)).build(); //no hash?!
        Chat chat2 = Chat.builder().users(List.of(user2, user3)).build();
//        Chat chat1 = new Chat(List.of(user1, user2));
//        Chat chat2 = new Chat(List.of(user2, user3));

        chatRepository.save(chat1);
        chatRepository.save(chat2);

        message1_chat1.setChat(chat1);
        message2_chat1.setChat(chat1);
        message1_chat2.setChat(chat2);
        message2_chat2.setChat(chat2);

        messageRepository.save(message1_chat1);
        messageRepository.save(message2_chat1);
        messageRepository.save(message1_chat2);
        messageRepository.save(message2_chat2);

/////////////////////////////////////////////////Favourite////////////////////////////////////////////////////////////
        Favorite favorite1 = Favorite.builder()
                .shops(List.of(shop1))
                .items(List.of(item1))
                .user(user1)
                .build();
        Favorite favorite2 = Favorite.builder()
                .shops(List.of(shop2))
                .items(List.of(item2))
                .user(user2)
                .build();
        Favorite favorite3 = Favorite.builder()
                .shops(List.of(shop3))
                .items(List.of(item3))
                .user(user3)
                .build();
        favoriteRepository.save(favorite1);
        favoriteRepository.save(favorite2);
        favoriteRepository.save(favorite3);

/////////////////////////////////////////////////Orders////////////////////////////////////////////////////////////
        Order order1 = Order.builder()
                .orderDate(Calendar.getInstance())
                .expectedDeliveryDate(Calendar.getInstance())
                .grandTotal(item1.getPrice().add(item2.getPrice()))
                .currency("dollar")
                .description("help me")
                .status(Status.START)
                .user(user1)
                .address(address1)
                //.itemsInOrder(Set.of(item1, item2))
                .build();
        Order order2 = Order.builder()
                .orderDate(Calendar.getInstance())
                .expectedDeliveryDate(Calendar.getInstance())
                .grandTotal(item3.getPrice().add(item2.getPrice()))
                .currency("dollar")
                .description("help me")
                .status(Status.DELIVERED)
                .user(user3)
                .address(address2)
                //.itemsInOrder(Set.of(item3, item2))
                .build();
        ordersRepository.save(order1);
        ordersRepository.save(order2);
        item1.setOrders(List.of(order1));
        //itemRepository.save(item1);

/////////////////////////////////////////////////Review////////////////////////////////////////////////////////////
        Review reviewItem = Review.builder()
                .date(GregorianCalendar.getInstance().getTime())
                .dignity("dignity")
                .flaw("flaw")
                .text("textReview")
                .rating(3)
                .user(user1)
                .shop(shop1)
                .item(item1)
                .isModerateAccept(false)
                .isModerateAccept(false)
                .moderatedRejectReason(null)
                .build();
        reviewRepository.save(reviewItem);
        Review reviewShop = Review.builder()
                .date(GregorianCalendar.getInstance().getTime())
                .dignity("dignity")
                .flaw("flaw")
                .text("textReview")
                .rating(2)
                .user(user2)
                .shop(shop2)
                .item(item2)
                .isModerateAccept(false)
                .isModerateAccept(false)
                .moderatedRejectReason(null)
                .build();
        reviewRepository.save(reviewShop);

/////////////////////////////////////////////////UserInfo////////////////////////////////////////////////////////////
        UserInfo userInfo1 = UserInfo.builder()
                .age(44)
                .phone("+5388881")
                .firstName("Alex1")
                .lastName("Vazovski1")
                .birthday(Calendar.getInstance())
                .gender(Gender.MALE)
                .user(user1)
                .build();
        UserInfo userInfo2 = UserInfo.builder()
                .age(44)
                .phone("+5388882")
                .firstName("Alex2")
                .lastName("Vazovski2")
                .birthday(Calendar.getInstance())
                .gender(Gender.FEMALE)
                .user(user2)
                .build();
        UserInfo userInfo3 = UserInfo.builder()
                .age(44)
                .phone("+5388883")
                .firstName("Alex3")
                .lastName("Vazovski3")
                .birthday(Calendar.getInstance())
                .gender(Gender.UNKNOWN)
                .user(user3)
                .build();
        userInfoRepository.save(userInfo1);
        userInfoRepository.save(userInfo2);
        userInfoRepository.save(userInfo3);

/////////////////////////////////////////////////CartItem////////////////////////////////////////////////////////////
        CartItem cartItem1 = CartItem.builder()
                .quantity(5)
                .shop(null)
                .user(user1)
                .build();
        CartItem cartItem2 = CartItem.builder()
                .quantity(2)
                .shop(null)
                .user(user2)
                .build();
        CartItem cartItem3 = CartItem.builder()
                .quantity(3)
                .shop(null)
                .user(user3)
                .build();
        cartItemRepository.save(cartItem1);
        cartItemRepository.save(cartItem2);
        cartItemRepository.save(cartItem3);


/////////////////////////////////////////////////Admin/Moderator//////////////////////////////////////////////////////
        User admin1 = User.builder()
                .email("admin1@mail.com")
                .username("admin1")
                .password(passwordEncoder.passwordEncoder().encode("admin1"))
                .activate(true)
                .activationCode("some_code")
                .isUsing2FA(false)
                .secret("secret?")
                .role(Roles.ADMIN)
                .userInfo(null)
                .favorite(null)
                .address(address1)
                .images(null)
                .coupons(null)
                .carts(null)
                .orders(null)
                .reviews(null)
                .shops(null)
                .discounts(null)
                .messages(null)
                .chats(null)
                .feedbacks(null)
                .build();
        User admin2 = User.builder()
                .email("admin2@mail.com")
                .username("admin2")
                .password(passwordEncoder.passwordEncoder().encode("admin2"))
                .activate(false)
                .activationCode("some_code")
                .isUsing2FA(true)
                .secret("secret?")
                .role(Roles.ADMIN)
                .userInfo(null)
                .favorite(null)
                .address(address1)
                .images(null)
                .coupons(null)
                .carts(null)
                .orders(null)
                .reviews(null)
                .shops(null)
                .discounts(null)
                .messages(null)
                .chats(null)
                .feedbacks(null)
                .build();
        User moderator1 = User.builder()
                .email("moderator1@mail.com")
                .username("moderator1")
                .password(passwordEncoder.passwordEncoder().encode("moderator1"))
                .activate(true)
                .activationCode("some_code")
                .isUsing2FA(false)
                .secret("secret?")
                .role(Roles.MODERATOR)
                .userInfo(null)
                .favorite(null)
                .address(address2)
                .images(null)
                .coupons(null)
                .carts(null)
                .orders(null)
                .reviews(null)
                .shops(null)
                .discounts(null)
                .messages(null)
                .chats(null)
                .feedbacks(null)
                .build();
        userRepository.save(admin1);
        userRepository.save(admin2);
        userRepository.save(moderator1);
    }
}
