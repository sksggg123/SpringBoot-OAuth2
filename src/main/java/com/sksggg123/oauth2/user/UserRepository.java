package com.sksggg123.oauth2.user;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * author      : gwonbyeong-yun <sksggg123>
 * <p>
 * info        : email   - sksggg123
 * : github - github.com/sksggg123
 * : blog   - sksggg123.github.io
 * <p>
 * project     : oauth2
 * <p>
 * create date : 2019-05-05 13:26
 */
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
