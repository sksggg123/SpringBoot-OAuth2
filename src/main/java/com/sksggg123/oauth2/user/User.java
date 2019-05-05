package com.sksggg123.oauth2.user;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

/**
 * author      : gwonbyeong-yun <sksggg123>
 * <p>
 * info        : email   - sksggg123
 * : github - github.com/sksggg123
 * : blog   - sksggg123.github.io
 * <p>
 * project     : oauth2
 * <p>
 * create date : 2019-05-05 13:22
 */
@Entity
public class User {

    @Id
    @GeneratedValue
    private Long id;

    private String username;

    private String password;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                '}';
    }
}
