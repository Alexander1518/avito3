package com.amr.project.service.impl;

import com.amr.project.converter.CycleAvoidingMappingContext;
import com.amr.project.converter.mappers.ImageMapper;
import com.amr.project.converter.mappers.UserMapper;
import com.amr.project.dao.ImageRepository;
import com.amr.project.dao.UserRepository;
import com.amr.project.model.Mail;
import com.amr.project.model.dto.ImageDto;
import com.amr.project.model.dto.UserDto;
import com.amr.project.model.entity.Image;
import com.amr.project.model.entity.User;
import com.amr.project.model.enums.Provider;
import com.amr.project.model.enums.Roles;
import com.amr.project.service.abstracts.UserService;
import com.amr.project.service.email.MailSender;
import com.amr.project.util.EmailUserAssistant;
import com.amr.project.webapp.config.security.handler.PassEncoder;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private MailSender mailSender;
    private EmailUserAssistant emailUserAssistant;
    private final PassEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final ImageRepository imageRepository;
    private final ImageMapper imageMapper;

    @Autowired
    public UserServiceImpl(MailSender mailSender, EmailUserAssistant emailUserAssistant,
                           PassEncoder passwordEncoder, UserRepository userRepository,
                           UserMapper userMapper, ImageRepository imageRepository,
                           ImageMapper imageMapper) {
        this.mailSender = mailSender;
        this.emailUserAssistant = emailUserAssistant;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.userMapper = userMapper;
        this.imageRepository = imageRepository;
        this.imageMapper = imageMapper;
    }

    public static String APP_NAME = "SpringRegistration";
    public static String QR_PREFIX =
            "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=";


    @Override
    public List<UserDto> getAllUsers() {
        List<User> users = userRepository.findAll();
        return userMapper.toDtoList(users, new CycleAvoidingMappingContext());
    }

    @Override
    public UserDto getUserById(Long id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isEmpty()) {
            throw new NullPointerException("User not found");
        }
        UserDto userDto = userMapper.toDto(user.get(), new CycleAvoidingMappingContext());
        return userDto;
    }

    @Override
    public void updateUser(UserDto user) {
        User user1 = userMapper.toEntity(user, new CycleAvoidingMappingContext());
        if (user.getPassword().isEmpty()){
            user1.setPassword(getUserById(user.getId()).getPassword());
        } else {
            user.setPassword(passwordEncoder.passwordEncoder().encode(user.getPassword()));
        }
        mailSender.send(emailUserAssistant.trackedEmailUserUpdate(user1));
        userRepository.saveAndFlush(user1);
    }

    @Override
    public void deleteUserById(Long id) {
        mailSender.send(emailUserAssistant.trackedEmailUserDelete(userRepository.getById(id)));
        userRepository.deleteById(id);
    }

    @Override
    public void saveUser(UserDto user) {
        User user1 = userMapper.toEntity(user, new CycleAvoidingMappingContext());
        user1.setActivate(false);
        user1.setRole(Roles.USER);
        user1.setActivationCode(UUID.randomUUID().toString());
        user1.setPassword(passwordEncoder.passwordEncoder().encode(user.getPassword()));

        if (user1.getEmail() != null) {
            String message = "<a href=http://localhost:8888/registrationConfirm?" +
                    "&code=" + user.getActivationCode() +
                    "> + Verify email and activate account</a>";
            Mail verificationMail = new Mail();
            verificationMail.setTo(user1.getEmail());
            verificationMail.setText(message);
            mailSender.send(verificationMail);
        }
        userRepository.saveAndFlush(user1);
    }

    @Override
    public User getUserByEmail(String email) {
        return userRepository.getUserByEmail(email);
    }

    public String activateUser(String code) {
        User user = userRepository.findByActivationCode(code);
        if (user == null) {
            return "user not found";
        }
        if (user.getActivationCode().equals(code)) {
            user.setActivate(true);
        }
        user.setActivationCode(null);
        return "user activated";
    }

    @Override
    public String generateQRUrl(User user) throws UnsupportedEncodingException {
        return QR_PREFIX + URLEncoder.encode(String.format(
                        "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                        APP_NAME, user.getEmail(), user.getSecret(), APP_NAME),
                "UTF-8");
    }

    @Override
    public List<ImageDto> getUserWithPicture(User user, byte[] bytes) {
        boolean fileMatchWithDb = false;
        List<Image> imageList = new ArrayList<>();

        for (Image im : user.getImages()) {
            if (Arrays.equals(im.getPicture(), bytes)) {
                im.setIsMain(true);
                fileMatchWithDb = true;
            } else {
                im.setIsMain(false);
            }
            imageList.add(im);
        }
        if (!fileMatchWithDb) {
            Image image = Image.builder()
                    .isMain(true)
                    .picture(bytes)
                    .build();
            imageRepository.saveAndFlush(image);
            imageList.add(imageRepository.findByPicture(bytes));
        }
        user.setImages(imageList);
        userRepository.saveAndFlush(user);
        return imageMapper.toDtoList(user.getImages(), new CycleAvoidingMappingContext());
    }

    @Override
    public void processOAuthPostLogin(String username) {
        User existUser = userRepository.getUserByUsername(username);

        if (existUser == null) {
            User newUser = new User();
            newUser.setUsername(username);
            newUser.setProvider(Provider.GOOGLE);

            userRepository.save(newUser);
        }
    }
}
