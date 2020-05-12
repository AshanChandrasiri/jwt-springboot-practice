package com.example.jwt.jwtsecurity.config.mongo.changelogs;

import com.example.jwt.jwtsecurity.model.Role;
import com.example.jwt.jwtsecurity.model.User;
import com.example.jwt.jwtsecurity.model.enumeration.ERole;
import com.github.mongobee.changeset.ChangeLog;
import com.github.mongobee.changeset.ChangeSet;
import org.springframework.data.mongodb.core.MongoTemplate;

import java.util.HashSet;

@ChangeLog
public class InitialValuesChangeLog {

    @ChangeSet(order = "001", id = "insertUserToTestAuthentication", author = "admin")
    public void insertUserToTestAuthentication(MongoTemplate mongoTemplate) {

        Role role1 = new Role();
        role1.setName(ERole.ROLE_ADMIN);
        mongoTemplate.save(role1);

        Role role2 = new Role();
        role2.setName(ERole.ROLE_USER);
        mongoTemplate.save(role2);
    }

}
