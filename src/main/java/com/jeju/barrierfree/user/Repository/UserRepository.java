package com.jeju.barrierfree.user.Repository;

import com.jeju.barrierfree.user.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

}
